#include "OnlineMachine.h"

#include "Processor/Machine.h"
#include "Processor/OnlineOptions.h"
#include "Math/Setup.h"
#include "Protocols/Share.h"
#include "Tools/ezOptionParser.h"
#include "Networking/Server.h"
#include "Networking/CryptoPlayer.h"
#include <iostream>
#include <map>
#include <string>
#include <stdio.h>

#include "Protocols/Replicated.hpp"
#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/MAC_Check_Base.hpp"

using namespace std;

template<class V>
OnlineMachine::OnlineMachine(int argc, const char** argv, ez::ezOptionParser& opt,
        OnlineOptions& online_opts, int nplayers, V) :
        argc(argc), argv(argv), online_opts(online_opts),
        use_encryption(false),
        opt(opt), nplayers(nplayers)
{
    opt.add(
          "5000", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port number base to attempt to start connections from (default: 5000)", // Help description.
          "-pn", // Flag token.
          "--portnumbase" // Flag token.
    );
    opt.add(
          "", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Port to listen on (default: port number base + player number)", // Help description.
          "-mp", // Flag token.
          "--my-port" // Flag token.
    );
    opt.add(
          "localhost", // Default.
          0, // Required?
          1, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Host where Server.x or party 0 is running to coordinate startup "
          "(default: localhost). "
          "Ignored if --ip-file-name is used.", // Help description.
          "-h", // Flag token.
          "--hostname" // Flag token.
    );
    opt.add(
      "", // Default.
      0, // Required?
      1, // Number of args expected.
      0, // Delimiter if expecting multiple args.
      "Filename containing list of party ip addresses. Alternative to --hostname and running Server.x for startup coordination.", // Help description.
      "-ip", // Flag token.
      "--ip-file-name" // Flag token.
    );

    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Use external server. "
          "Default is to coordinate through player 0.", // Help description.
          "-ext-server", // Flag token.
          "--external-server" // Flag token.
    );

    opt.parse(argc, argv);
    opt.resetArgs();
}

inline
DishonestMajorityMachine::DishonestMajorityMachine(int argc,
        const char** argv, ez::ezOptionParser& opt, OnlineOptions& online_opts,
        int nplayers) :
        DishonestMajorityMachine(argc, argv, opt, online_opts, gf2n())
{
    assert(nplayers == 0);
}

template<class V>
DishonestMajorityMachine::DishonestMajorityMachine(int argc, const char** argv,
        ez::ezOptionParser& opt, OnlineOptions& online_opts, V, int nplayers) :
        OnlineMachine(argc, argv, opt, online_opts, nplayers, V())
{
    opt.example = string() + argv[0] + " -p 0 -N 2 sample-prog\n" + argv[0]
            + " -h localhost -p 1 -N 2 sample-prog\n";

    opt.add(
          "", // Default.
          0, // Required?
          0, // Number of args expected.
          0, // Delimiter if expecting multiple args.
          "Use encrypted channels.", // Help description.
          "-e", // Flag token.
          "--encrypted" // Flag token.
    );
    online_opts.finalize(opt, argc, argv);

    use_encryption = opt.isSet("--encrypted");

    start_networking();
}

inline
void OnlineMachine::start_networking()
{
    string hostname, ipFileName;
    int pnbase;
    int my_port;

    opt.get("--portnumbase")->getInt(pnbase);
    opt.get("--hostname")->getString(hostname);
    opt.get("--ip-file-name")->getString(ipFileName);

    ez::OptionGroup* mp_opt = opt.get("--my-port");
    if (mp_opt->isSet)
      mp_opt->getInt(my_port);
    else
      my_port = Names::DEFAULT_PORT;

    int mynum = online_opts.playerno;
    int playerno = online_opts.playerno;

    if (ipFileName.size() > 0) {
      if (my_port != Names::DEFAULT_PORT)
        throw runtime_error("cannot set port number when using IP file");
      if (nplayers == 0 and opt.isSet("-N"))
        opt.get("-N")->getInt(nplayers);
      playerNames.init(playerno, pnbase, ipFileName, nplayers);
    } else {
      if (not opt.get("-ext-server")->isSet)
      {
        if (nplayers == 0)
          opt.get("-N")->getInt(nplayers);
        Server::start_networking(playerNames, mynum, nplayers,
            hostname, pnbase, my_port);
      }
      else
      {
        cerr << "Relying on external Server.x" << endl;
        playerNames.init(playerno, pnbase, my_port, hostname.c_str());
      }
    }
}

inline
Player* OnlineMachine::new_player(const string& id_base)
{
    if (use_encryption)
        return new CryptoPlayer(playerNames, id_base);
    else
        return new PlainPlayer(playerNames, id_base);
}

template<class T, class U>
int OnlineMachine::run()
{
    if (online_opts.has_option("throw_exceptions"))
        return run_with_error<T, U>();
    else
    {
        try
        {
            return run_with_error<T, U>();
        }
        catch (exception& e)
        {
            cerr << "Fatal error: " << e.what() << endl;
            exit(1);
        }
    }
}

template<class T, class U>
int OnlineMachine::run_with_error()
{
#ifndef INSECURE
    try
#endif
    {
        Machine<T, U>(playerNames, use_encryption, online_opts).run(
                online_opts.progname);

        if (online_opts.verbose)
          {
            cerr << "Command line:";
            for (int i = 0; i < argc; i++)
              cerr << " " << argv[i];
            cerr << endl;
          }
    }
#ifndef INSECURE
    catch(...)
    {
        if (not online_opts.live_prep)
            thread_info<T, U>::purge_preprocessing(playerNames, 0);
        throw;
    }
#endif

    return 0;
}
