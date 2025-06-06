
#include "Processor/Program.h"
#include "Processor/Online-Thread.h"
#include "Tools/time-func.h"
#include "Processor/Data_Files.h"
#include "Processor/Machine.h"
#include "Processor/Processor.h"
#include "Networking/CryptoPlayer.h"
#include "Protocols/ShuffleSacrifice.h"
#include "Protocols/LimitedPrep.h"
#include "FHE/FFT.h"

#include "Processor/Processor.hpp"
#include "Processor/Instruction.hpp"
#include "Processor/Input.hpp"
#include "Protocols/LimitedPrep.hpp"
#include "Protocols/MalRepRingPrep.hpp"
#include "GC/BitAdder.hpp"

#include <iostream>
#include <fstream>
#include <pthread.h>
using namespace std;


template<class sint, class sgf2n>
template<class T>
void thread_info<sint, sgf2n>::print_usage(ostream &o,
        const vector<T>& regs, const char* name)
{
  ::print_usage(o, name, regs.capacity());
}

template<class sint, class sgf2n>
void thread_info<sint, sgf2n>::Sub_Main_Func()
{
  bigint::init_thread();

  auto tinfo = this;
  Machine<sint, sgf2n>& machine=*(tinfo->machine);
  vector<Program>& progs                = machine.progs;

  int num=tinfo->thread_num;
  BaseMachine::s().thread_num = num;

  auto& queues = machine.queues[num];
  auto& opts = machine.opts;
  queues->next();
  ThreadQueue::thread_queue = queues;

#ifdef DEBUG_THREADS
  fprintf(stderr, "\tI am in thread %d\n",num);
#endif
  Player* player;
  string id = "thread" + to_string(num);
  if (machine.use_encryption)
    {
#ifdef VERBOSE_OPTIONS
      cerr << "Using encrypted single-threaded communication" << endl;
#endif
      player = new CryptoPlayer(*(tinfo->Nms), id);
    }
  else if (!opts.receive_threads or opts.direct)
    {
#ifdef VERBOSE_OPTIONS
      cerr << "Using single-threaded receiving" << endl;
#endif
      player = new PlainPlayer(*(tinfo->Nms), id);
    }
  else
    {
#ifdef VERBOSE_OPTIONS
      cerr << "Using player-specific threads for receiving" << endl;
#endif
      player = new ThreadPlayer(*(tinfo->Nms), id);
    }
  Player& P = *player;
#ifdef DEBUG_THREADS
  fprintf(stderr, "\tSet up player in thread %d\n",num);
#endif

  typename sgf2n::MAC_Check* MC2;
  typename sint::MAC_Check*  MCp;

  if (opts.direct)
    {
#ifdef VERBOSE_OPTIONS
      cerr << "Using direct communication." << endl;
#endif
      MC2 = new typename sgf2n::Direct_MC(*(tinfo->alpha2i));
      MCp = new typename sint::Direct_MC(*(tinfo->alphapi));
    }
  else
    {
#ifdef VERBOSE_OPTIONS
      cerr << "Using indirect communication." << endl;
#endif
      MC2 = new typename sgf2n::MAC_Check(*(tinfo->alpha2i), opts.opening_sum, opts.max_broadcast);
      MCp = new typename sint::MAC_Check(*(tinfo->alphapi), opts.opening_sum, opts.max_broadcast);
    }

  // Allocate memory for first program before starting the clock
  processor = new Processor<sint, sgf2n>(tinfo->thread_num,P,*MC2,*MCp,machine,progs.at(thread_num > 0));
  auto& Proc = *processor;

  // don't count communication for initialization
  P.reset_stats();

  bool flag=true;
  int program=-3; 
  // int exec=0;

  typedef typename sint::bit_type::part_type BT;

  // synchronize
#ifdef DEBUG_THREADS
  cerr << "Locking for sync of thread " << num << endl;
#endif
  queues->finished({});

  DataPositions actual_usage(P.num_players());
  Timer thread_timer(CLOCK_THREAD_CPUTIME_ID), wait_timer;
  thread_timer.start();
  TimerWithComm timer, online_timer, online_prep_timer;
  timer.start();

  while (flag)
    { // Wait until I have a program to run
      wait_timer.start();
      ThreadJob job = queues->next();
      program = job.prognum;
      wait_timer.stop();
#ifdef DEBUG_THREADS
      printf("\tRunning program %d/job %d in thread %d\n", program, job.type,
          num);
#endif

      if (program==-1)
        { flag=false;
#ifdef DEBUG_THREADS
          fprintf(stderr, "\tThread %d terminating\n",num);
#endif
        }
      else if (job.type == BITADD_JOB)
        {
          auto& party = GC::ShareThread<typename sint::bit_type>::s();
          if (job.arg < 0)
            {
              SubProcessor<BT> bit_proc(party.MC->get_part_MC(),
                  Proc.Procp.bit_prep, P);
              BitAdder().add(*(vector<vector<BT>>*) job.output,
                  *(vector<vector<vector<BT>>>*) job.input, job.begin, job.end,
                  bit_proc, job.length, -1, job.supply);
            }
          else
            {
              // too late for preprocessing for security reasons
              assert(job.supply);
              LimitedPrep<BT> limited_prep;
              SubProcessor<BT> bit_proc(party.MC->get_part_MC(),
                  limited_prep, P);
              BitAdder().add(*(vector<vector<BT>>*) job.output,
                  *(vector<vector<vector<BT>>>*) job.input, job.begin, job.end,
                  bit_proc, job.length, -1, job.supply);
            }
          queues->finished(job);
        }
      else if (job.type == DABIT_JOB)
        {
          dynamic_cast<RingPrep<sint>&>(Proc.DataF.DataFp).template
                  buffer_dabits_without_check<0>(
              *(vector<dabit<sint>>*) job.output, job.begin, job.end,
              Proc.Procp.bit_prep);
          queues->finished(job);
        }
      else if (job.type == MULT_JOB)
        {
          Proc.Procp.protocol.multiply(*(PointerVector<sint>*) job.output,
              *(vector<pair<sint, sint>>*) job.input, job.begin, job.end,
              Proc.Procp);
          queues->finished(job);
        }
      else if (job.type == EDABIT_JOB)
        {
          dynamic_cast<RingPrep<sint>&>(Proc.DataF.DataFp).template
                  buffer_edabits_without_check<0>(
              job.length, *(vector<sint>*) job.output,
              *(vector<vector<BT>>*) job.output2, job.begin, job.end);
          queues->finished(job);
        }
      else if (job.type == PERSONAL_JOB)
        {
          auto &party = GC::ShareThread<typename sint::bit_type>::s();
          SubProcessor<BT> bit_proc(party.MC->get_part_MC(),
              Proc.Procp.bit_prep, P);
          dynamic_cast<RingPrep<sint>&>(Proc.DataF.DataFp).template
                  buffer_personal_edabits_without_check<0>(
              job.length, *(vector<sint>*) job.output,
              *(vector<vector<BT>>*) job.output2, bit_proc,
              job.arg, job.begin, job.end);
          queues->finished(job);
        }
      else if (job.type == SANITIZE_JOB)
        {
          dynamic_cast<RingPrep<sint>&>(Proc.DataF.DataFp).template
                  sanitize<0>(
              *(vector<edabit<sint>>*) job.output, job.length, job.arg,
              job.begin, job.end);
          queues->finished(job);
        }
      else if (job.type == EDABIT_SACRIFICE_JOB)
        {
          sint::LivePrep::edabit_sacrifice_buckets(
              *(vector<edabit<sint>>*) job.output, job.length, job.prognum,
              job.arg, Proc.Procp,
              job.begin, job.end, job.supply);
#ifdef DEBUG_THREADS
          printf("\tSignalling I have finished with job %d in thread %d\n",
              job.type, num);
#endif
          queues->finished(job);
        }
      else if (job.type == PERSONAL_TRIPLE_JOB)
        {
          auto &party = GC::ShareThread<typename sint::bit_type>::s();
          SubProcessor<BT> bit_proc(party.MC->get_part_MC(),
              *Proc.Procp.personal_bit_preps.at(job.arg), P);
          Proc.Procp.personal_bit_preps.at(job.arg)->buffer_personal_triples(
              *(vector<array<BT, 3>>*) job.output, job.begin, job.end);
          queues->finished(job);
        }
      else if (job.type == TRIPLE_SACRIFICE_JOB)
        {
          typedef typename sint::bit_type B;
          auto &party = GC::ShareThread<B>::s();
          TripleShuffleSacrifice<B>().triple_sacrifice(
              *(vector<array<B, 3>>*) job.output,
              *(vector<array<B, 3>>*) job.input, *party.P, *party.MC, job.begin,
              job.end);
          queues->finished(job);
        }
      else if (job.type == CHECK_JOB)
        {
          Proc.check();
          queues->finished(job);
        }
      else if (job.type == FFT_JOB)
        {
          for (int i = job.begin; i < job.end; i++)
            FFT_Iter2_body(*(vector<modp>*) job.output,
                *(vector<modp>*) job.input, i, job.length,
                *(Zp_Data*) job.supply);
          queues->finished(job);
        }
      else if (job.type == CIPHER_PLAIN_MULT_JOB)
        {
          cipher_plain_mult(job, sint::triple_matmul);
          queues->finished(job);
        }
      else if (job.type == MATRX_RAND_MULT_JOB)
        {
          matrix_rand_mult(job, sint::triple_matmul);
          queues->finished(job);
        }
      else
        { // RUN PROGRAM
#ifdef DEBUG_THREADS
          printf("\tClient %d about to run %d\n",num,program);
#endif
          online_timer.start(P.total_comm());
          online_prep_timer -= Proc.DataF.total_time();
          Proc.reset(progs[program], job.arg);

          // Bits, Triples, Squares, and Inverses skipping
          Proc.DataF.seekg(job.pos);
          // reset for actual usage
          Proc.DataF.reset_usage();
             
          //printf("\tExecuting program");
          // Execute the program
          progs[program].execute(Proc);

          // make sure values used in other threads are safe
          Proc.check();

          // prevent mangled output
          cout.flush();

          actual_usage.increase(Proc.DataF.get_usage());

         if (progs[program].usage_unknown())
           { // communicate file positions to main thread
             job.pos.increase(Proc.DataF.get_usage());
           }

#ifdef DEBUG_THREADS
          printf("\tSignalling I have finished with program %d"
              "in thread %d\n", program, num);
#endif
          online_timer.stop(P.total_comm());
          online_prep_timer += Proc.DataF.total_time();
          wait_timer.start();
          queues->finished(job, P.total_comm());
	 wait_timer.stop();
       }  
    }

  // final check
  online_timer.start(P.total_comm());
  online_prep_timer -= Proc.DataF.total_time();
  Proc.check();
  online_timer.stop(P.total_comm());
  online_prep_timer += Proc.DataF.total_time();

  if (machine.opts.file_prep_per_thread)
    Proc.DataF.prune();

  wait_timer.start();
  queues->next();
  wait_timer.stop();

#ifdef VERBOSE
  if (MC2->number() + MCp->number() > 0)
    cerr << num << " : MAC Checking" << endl;
  if (MC2->number())
    cerr << "\tMC2.number=" << MC2->number() << endl;
  if (MCp->number())
    cerr << "\tMCp.number=" << MCp->number() << endl;

  cerr << "Thread " << num << " timer: " << thread_timer.elapsed() << endl;
  cerr << "Thread " << num << " wait timer: " << wait_timer.elapsed() << endl;

  cerr << "Register usage: ";
  print_usage(cerr, Proc.Procp.get_S(), "sint");
  print_usage(cerr, Proc.Procp.get_C(), "cint");
  print_usage(cerr, Proc.Proc2.get_S(), "sgf2n");
  print_usage(cerr, Proc.Proc2.get_C(), "cgf2n");
  print_usage(cerr, Proc.Procb.S, "sbits");
  print_usage(cerr, Proc.Procb.C, "cbits");
  print_usage(cerr, Proc.get_Ci(), "regint");
  cerr << endl;
#endif

  if (num == 0 and OnlineOptions::singleton.verbose
      and machine.queues.size() > 1)
    {
      cerr << "Main thread communication:" << endl;
      P.total_comm().print();
    }

  // wind down thread by thread
  machine.stats += Proc.stats;
  queues->timers["wait"] = wait_timer + queues->wait_timer;
  timer.stop(P.total_comm());
  queues->timers["online"] = online_timer - online_prep_timer - queues->wait_timer;
  queues->timers["prep"] = timer - queues->timers["wait"] - queues->timers["online"];

  assert(Proc.share_thread.protocol);
  queues->timers["random"] = Proc.Procp.protocol.randomness_time()
      + Proc.Proc2.protocol.randomness_time()
      + Proc.share_thread.protocol->randomness_time();

  NamedStats stats;
  stats["integer multiplications"] = Proc.Procp.protocol.counter;
  stats["integer multiplication rounds"] = Proc.Procp.protocol.rounds;
  stats["integer dot products"] = Proc.Procp.protocol.dot_counter;
  stats["probabilistic truncations"] = Proc.Procp.protocol.trunc_pr_counter;
  stats["probabilistic truncations (big gap)"] = Proc.Procp.protocol.trunc_pr_big_counter;
  stats["probabilistic truncation rounds"] = Proc.Procp.protocol.trunc_rounds;
  stats["ANDs"] = Proc.share_thread.protocol->bit_counter;
  stats["AND rounds"] = Proc.share_thread.protocol->rounds;
  stats["integer openings"] = MCp->values_opened;
  stats["integer inputs"] = Proc.Procp.input.values_input;
  for (auto x : Proc.Procp.shuffler.stats)
    stats["shuffles of length " + to_string(x.first)] = x.second;

  try
  {
      auto proc = dynamic_cast<RingPrep<sint>&>(Proc.DataF.DataFp).bit_part_proc;
      if (proc)
        stats["ANDs in preprocessing"] = proc->protocol.bit_counter;
  }
  catch (...)
  {
  }

  try
  {
      auto protocol = dynamic_cast<BitPrep<sint>&>(Proc.DataF.DataFp).protocol;
      if (protocol)
        stats["integer multiplications in preprocessing"] = protocol->counter;
  }
  catch (...)
  {
  }

  // prevent faulty usage message
  Proc.DataF.set_usage(actual_usage);
  delete processor;

  queues->finished(actual_usage, P.total_comm(), stats);

  delete MC2;
  delete MCp;
  delete player;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  OPENSSL_thread_stop();
#endif
}


template<class sint, class sgf2n>
void* thread_info<sint, sgf2n>::Main_Func(void* ptr)
{
  auto& ti = *(thread_info<sint, sgf2n>*)(ptr);
  if (OnlineOptions::singleton.has_option("throw_exceptions"))
    ti.Main_Func_With_Purge();
  else
    {
      try
      {
          ti.Main_Func_With_Purge();
      }
      catch (exception& e)
      {
          cerr << "Fatal error: " << e.what() << endl;
          exit(1);
      }
    }
  return 0;
}

template<class sint, class sgf2n>
void thread_info<sint, sgf2n>::Main_Func_With_Purge()
{
  auto& ti = *this;
#ifdef INSECURE
  ti.Sub_Main_Func();
#else
  if (ti.machine->opts.live_prep)
    ti.Sub_Main_Func();
  else
    try
    {
      ti.Sub_Main_Func();
    }
    catch (setup_error&)
    {
      throw;
    }
    catch (...)
    {
      purge_preprocessing(machine->get_N(), thread_num);
      throw;
    }
#endif
}


template<class sint, class sgf2n>
void thread_info<sint, sgf2n>::purge_preprocessing(const Names& N, int thread_num)
{
  cerr << "Purging preprocessed data because something is wrong" << endl;
  try
  {
      Data_Files<sint, sgf2n> df(N, thread_num);
      df.purge();
      DataPositions pos;
      Sub_Data_Files<typename sint::bit_type> bit_df(N, pos, thread_num);
      bit_df.get_part();
      bit_df.purge();
  }
  catch(setup_error&)
  {
  }
  catch(exception& e)
  {
      cerr << "Purging failed. This might be because preprocessed data is incomplete." << endl
          << "SECURITY FAILURE; YOU ARE ON YOUR OWN NOW!" << endl;
      cerr << "Reason: " << e.what() << endl;
  }
}
