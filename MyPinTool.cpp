/*
 * Copyright 2002-2020 Intel Corporation.
 *
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 *
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::ofstream;
using std::ios;
using std::string;
using std::endl;

ofstream OutFile;

// The running count of instructions is kept here
// make it static to help the compiler optimize docount
// UINT64 i = 0;
ADDRINT prev = 0;


// Pin calls this function every time a new img is loaded
// It can instrument the image, but this example does not
// Note that imgs (including shared libraries) are loaded lazily

VOID ImageLoad(IMG img, VOID* v)
{

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {
            // Prepare for processing of RTN, an  RTN is not broken up into BBLs,
            // it is merely a sequence of INSs 
            RTN_Open(rtn);

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
            {
                    if (prev != 0 && IMG_IsMainExecutable(img)) 
                    {
                        OutFile << "\"0x" << std::hex << prev << "\" -> \"0x" << std::hex << INS_Address(ins) << "\";\r\n" << endl;
                    }
                    prev = INS_Address(ins);
           
            }
            // to preserve space, release data associated with RTN after we have processed it
            RTN_Close(rtn);
        }
    }

}


KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "dotgraph.dot", "specify output file name");


// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    OutFile.setf(ios::showbase);
    OutFile << "}\r\n" << endl;
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the applicatio
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool creates a a dotgraph where there exists an edge between every instruction during execution." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());
    OutFile << "digraph controlflow {\r\n" << endl;

    // Register Instruction to be called to instrument instructions
    // TRACE_AddInstrumentFunction(Trace, 0);

    // Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    // Register Instruction to be called to instrument instructions
    //INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits

    PIN_AddFiniFunction(Fini, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
