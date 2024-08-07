/*
 * OutputRedirection.h
 *
 */

#ifndef TOOLS_SWITCHABLEOUTPUT_H_
#define TOOLS_SWITCHABLEOUTPUT_H_

#include <iostream>
#include <fstream>
using namespace std;

class SwitchableOutput
{
    ostream* out;

public:
    SwitchableOutput(bool on = true)
    {
        activate(false);
        activate(on);
    }

    void activate(bool on)
    {
        if (on)
        {
            if (out == 0)
                out = &cout;
        }
        else
            out = 0;
    }

    void redirect_to_file(ofstream& out_file)
    {
        out = &out_file;
    }

    template<class T>
    SwitchableOutput& operator<<(const T& value)
    {
        if (out)
            *out << value;
        return *this;

        cout << flush;
    }

    SwitchableOutput& operator<<(ostream& (*__pf)(ostream&))
    {
        if (out)
            *out << __pf;
        return *this;
    }

    void fill(char c)
    {
        if (out)
            out->fill(c);
    }

    void width(streamsize w)
    {
        if (out)
            out->width(w);
    }

    template<class T>
    void signed_output(const T& x)
    {
        if (out)
            x.output(*out, true, true);
    }
};

#endif /* TOOLS_SWITCHABLEOUTPUT_H_ */
