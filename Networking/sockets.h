#ifndef _sockets_h
#define _sockets_h

#include "Networking/data.h"

#include <errno.h>      /* Errors */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>   /* Wait for Process Termination */

#include <iostream>
using namespace std;

// default to one minute
#ifndef CONNECTION_TIMEOUT
#define CONNECTION_TIMEOUT 60
#endif

void error(const char *str, bool interrupted = false, size_t length = 0);

void set_up_client_socket(int& mysocket,const char* hostname,int Portnum);
void close_client_socket(int socket);

// send/receive integers
template<class T>
void send(T& socket, size_t a, size_t len);
template<class T>
void receive(T& socket, size_t& a, size_t len);


inline size_t send_non_blocking(int socket, octet* msg, size_t len)
{
#ifdef __APPLE__
  int j = send(socket,msg,min(len,10000lu),MSG_DONTWAIT);
#else
  int j = send(socket,msg,len,MSG_DONTWAIT);
#endif
  if (j < 0)
    {
      if (errno != EINTR and errno != EAGAIN and errno != EWOULDBLOCK and
	  errno != ENOBUFS)
        { error("Sending error", true);  }
      else
        return 0;
    }
  return j;
}

inline void send(int socket,octet *msg,size_t len)
{
  size_t i = 0;
  long wait = 1;
  while (i < len)
    {
      size_t j = send_non_blocking(socket, msg + i, len - i);
      i += j;
      if (i > 0)
	wait = 1;
      else
	{
	  usleep(wait);
	  wait *= 2;
	}
    }
}

template<class T>
inline void send(T& socket, size_t a, size_t len)
{
  octet blen[8];
  encode_length(blen, a, len);
  send(socket, blen, len);
}

inline void receive(int socket,octet *msg,size_t len)
{
  size_t i=0;
  int fail = 0;
  long wait = 1;
  while (len-i>0)
    { int j=recv(socket,msg+i,len-i,0);
      // success first
      if (j > 0)
	{
	  i = i + j;
	  fail = 0;
	  wait = 1;
	}
      else if (j < 0)
        {
          if (errno == EAGAIN or errno == EINTR)
            {
              if (++fail > 25)
                error("Unavailable too many times", true);
              else
                {
                  usleep(wait *= 2);
                }
            }
          else
            { error("Receiving error", true, len - i); }
        }
      else
        throw closed_connection();
    }
}

template<class T>
inline void receive(T& socket, size_t& a, size_t len)
{
  octet blen[8];
  receive(socket, blen, len);
  a = decode_length(blen, len);
}

inline ssize_t check_non_blocking_result(ssize_t res)
{
  if (res < 0)
    {
      if (errno != EWOULDBLOCK)
        error("Non-blocking receiving error", true);
      return 0;
    }
  return res;
}

inline ssize_t receive_non_blocking(int socket, octet *msg, size_t len)
{
  ssize_t res = recv(socket, msg, len, MSG_DONTWAIT);
  return check_non_blocking_result(res);
}

inline ssize_t receive_all_or_nothing(int socket, octet *msg, ssize_t len)
{
  ssize_t res = recv(socket, msg, len, MSG_DONTWAIT | MSG_PEEK);
  check_non_blocking_result(res);
  if (res == len)
    {
      if (recv(socket, msg, len, 0) != len)
        error("All or nothing receiving error", true);
      return len;
    }
  else
    return 0;
}

#endif
