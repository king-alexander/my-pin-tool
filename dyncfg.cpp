
/*! @file
*  This is an example of the PIN tool that demonstrates some basic PIN APIs
*  and could serve as the starting point for developing your first PIN tool
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>

#include <sys/mman.h>

using std::cerr;
using std::string;
using std::endl;


/* ================================================================== */
// Global variables
/* ================================================================== */


struct AnalysisData
{
	std::set<ADDRINT> nodes;
	std::map<ADDRINT, std::set<ADDRINT>> edges;
	ADDRINT lastInst = 0;
};

std::map<THREADID, AnalysisData> threadData;

std::map<THREADID, bool> applicationThreads;

TLS_KEY analysisPtrKey;

ADDRINT baseAddr = 0;

PIN_RWMUTEX dataMutex;
PIN_MUTEX fMutex;

std::set<ADDRINT> printed;

std::ostream* out = nullptr;
std::ostream* cout = nullptr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "", "specify file name for DynCFG output");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

template<typename key, typename val>
using MappedSet = std::map<key, std::set<val>>;
template <typename Key, typename Value>
void MergeMappedSet(MappedSet<Key, Value>* target, const MappedSet<Key, Value>* with)
{
	for (auto& p : *with)
	{
		(*target)[p.first].insert(p.second.begin(), p.second.end());
	}
}

/*!
*  Print out help message.
*/
INT32 Usage()
{
	cerr << "This tool generates a dynamic control flow graph." << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

VOID doSave(void* ip)
{
	AnalysisData* ad = (AnalysisData*)PIN_GetThreadData(analysisPtrKey, PIN_ThreadId());
	assert(ad);
	ADDRINT addr = reinterpret_cast<ADDRINT>(ip);
	addr -= baseAddr;

	PIN_RWMutexReadLock(&dataMutex);
	ad->nodes.insert(addr);
	ad->edges[ad->lastInst].insert(addr);
	ad->lastInst = addr;
	PIN_RWMutexUnlock(&dataMutex);
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

bool IsMainImage(INS ins)
{
	ADDRINT addr = INS_Address(ins);

	IMG addrImg = IMG_FindByAddress(addr);

	if (!IMG_Valid(addrImg))
		return false;

	if (IMG_IsMainExecutable(addrImg))
	{
		if (!baseAddr)
			baseAddr = IMG_LoadOffset(addrImg);
		return true;
	}
	return false;
}

VOID Instruction(INS ins, VOID* v)
{
	if (IsMainImage(ins))
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doSave, IARG_INST_PTR, IARG_END);
}



VOID PrintDotGraph(AnalysisData* ad, ADDRINT addr)
{
	if (printed.find(addr) != printed.end())
		return;

	printed.insert(addr);

	for (ADDRINT a : ad->edges[addr])
	{
		*out << '"';
		if (addr == 0)
			*out << "START";
		else
			*out << std::hex << addr;
		*out << "\" -> \"" << std::hex << a << '"' << endl;
	}
}


VOID PrintDotGraph()
{
	*cout << "PrintDotGraph, locking mutex" << endl;
	PIN_MutexLock(&fMutex);


	assert(out);

	out->seekp(0);
	
	PIN_RWMutexWriteLock(&dataMutex);
	AnalysisData ad;

	for (auto& a : threadData)
	{
		ad.nodes.insert(a.second.nodes.begin(), a.second.nodes.end());
		MergeMappedSet(&ad.edges, &a.second.edges);
	}
	PIN_RWMutexUnlock(&dataMutex);



	printed.clear();
	*out << "digraph controlflow {" << endl;
	PrintDotGraph(&ad, 0);
	for (ADDRINT a : ad.nodes)
		PrintDotGraph(&ad, a);
	*out << "}";

	*cout << "PrintDotGraph, done" << endl;

	PIN_MutexUnlock(&fMutex);
}

/*!
* Print out analysis results.
* This function is called when the application exits.
* @param[in]   code            exit code of the application
* @param[in]   v               value specified by the tool in the
*                              PIN_AddFiniFunction function call
*/
VOID Fini(INT32 code, VOID* v)
{
	PrintDotGraph();
	if (out)
		delete out;
	out = nullptr;
}


bool IsAppThread(CONTEXT* ctxt)
{
	ADDRINT ip = PIN_GetContextReg(ctxt, REG_INST_PTR);

	IMG addrImg = IMG_FindByAddress(ip);

	if (!IMG_Valid(addrImg))
		return false;

	return IMG_IsMainExecutable(addrImg);
}


void ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID* v)
{
	*cout << "Thread started: " << threadIndex << endl;
	bool isAppThread = PIN_IsApplicationThread();
	if (isAppThread)
	{
		bool b = PIN_SetThreadData(analysisPtrKey, &threadData[threadIndex], threadIndex);
		assert(b);
	}
	else
		;//cerr << "Non-App thread " << PIN_IsApplicationThread() << endl;

	applicationThreads[threadIndex] = isAppThread;
}

void ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID* v)
{
	*cout << "Thread finished: " << threadIndex << endl;
	PrintDotGraph();
	//if(!applicationThreads[threadIndex])
	//	exit(1);
}


void testSafeCopy()
{
	size_t mmapSize = 4096;;
	char* mem = (char*)mmap(nullptr, mmapSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

	if(!mem)
	{
		std::cout << "FAIL mmap!" << endl;
		return;
	}

	std::cout << "Copying str to mem" << endl;
	const char* str = "Hello world!\n";
	memcpy(mem, str, strlen(str));

	std::cout << "MProtecting memory" << endl;
	//mprotect(mem, mmapSize, PROT_READ);

	const char* str2 = "Oh bye world!\n";

	EXCEPTION_INFO exc;
	std::cout << "PIN_SafeCopy memory" << endl;
	PIN_SafeCopyEx((void*)0x1345, str2, strlen(str2), &exc);

	if(strcmp(mem, str) == 0)
		*cout << "NOT overwritten" << endl;
	else if(strcmp(mem, str2))
		*cout << "Overwritten!!!" << endl;
	else
		*cout << "Weird Stuff!!!" << endl;
}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/
int main(int argc, char* argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
		return Usage();


	string fileName = KnobOutputFile.Value();

	cout = new std::ofstream("out.log", std::ios_base::out | std::ios_base::trunc);
	out = new std::ofstream(fileName.c_str(), std::ios_base::out | std::ios_base::trunc);

   testSafeCopy();

	if (!cout || cout->bad())
	{
		return 3;
	}

	PIN_MutexInit(&fMutex);
	PIN_RWMutexInit(&dataMutex);
	analysisPtrKey = PIN_CreateThreadDataKey(0);
	// Register function to be called to instrument traces
	INS_AddInstrumentFunction(Instruction, 0);

	PIN_AddFiniFunction(Fini, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	*cout << "===============================================" << endl;
	*cout << "This application is instrumented by DynCFG " << endl;

	if (!KnobOutputFile.Value().empty())
		*cout << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;

	*cout << "===============================================" << endl;

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

