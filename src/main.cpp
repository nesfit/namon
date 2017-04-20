/** 
 *  @file       main.cpp
 *  @brief      Main source file
 *  @details    Network Traffic Capturing With Application Tags,
 *              Bachelor's Thesis, FIT VUT Brno
 *  @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
 *  @date
 *   - Created: 18.02.2017 08:03
 *   - Edited:  02.04.2017 00:50
 *  @version:    1.0.0
 *  @todo       change tool name
 */

#include <iostream>             //  EXIT_*, cout, cerr

#if defined(_WIN32)
extern "C" {
#include "getopt_long.h"		//	getopt_long(), optarg
}
#else
#include <getopt.h>             //  getopt_long()
#endif

#include "capturing.hpp"        //  startCapture()
#include "debug.hpp"            //  D(), log(), setLogLevel()
#include "main.hpp"



extern const char * g_dev;


extern "C" const char * program_name = nullptr;

//! @brief  Struct with long options
static const struct option longopts[] = 
{
    { "interface",   required_argument, nullptr,    'i' },
    { "output-file", required_argument, nullptr,    'w' },
    { "verbosity",   optional_argument, nullptr,    'v' },
    { "help",        no_argument,       nullptr,    'h' },
    { nullptr,       0,                 nullptr,     0  }
};



int main (int argc, char *argv[])
{
    char const *oFilename = "tool_capturedTraffic.pcapng"; //! @todo zmenit tool za nazov nastroja

    int optionIndex = 0;
    char opt = 0;
	char *cp = nullptr;
	if ((cp = strrchr(argv[0], '/')) != nullptr)
		program_name = cp + 1;
	else
		program_name = argv[0];

    while((opt = getopt_long(argc, argv, "i:w:v::h", longopts, &optionIndex)) != -1)
    {
        switch (opt)
        {
            case 0:                          break;
            case 'i':   g_dev = optarg;      break;
            case 'w':   oFilename = optarg;  break;
			case 'v':   TOOL::setLogLevel(optarg); break;
            case 'h':   printUsage();   return EXIT_SUCCESS;
            default:    printUsage();   return EXIT_FAILURE;
        }
    }

    return startCapture(oFilename);
}


void printUsage()
{
    cout << "Usage: tool [-v[<level>]] [-i <interface>] [-w <output_filename>]" << endl; //! @todo zmenit nazov nastroja
    cout << "\t-v\tVerbosity level. Possible values are 0-3." << endl;
    cout << "\t-i\tCapturing interface." << endl;
    cout << "\t-w\tOutput file." << endl;
    cout << "\t-h\tPrints this message." << endl;
    cout << "Note: 'tool_capturedTraffic.pcapng' is used as default filename" << endl; // TODO zmenit nazov suboru
}
