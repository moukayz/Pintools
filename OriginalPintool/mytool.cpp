#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include "pin.H"

ofstream OutFile("dump.out", ofstream::out);
ofstream RtnStaticOutFile("rtn_dump_s.out", ofstream::out);  // Dump static infos about routines relative to the binary
//ofstream RtnDynamicOutFile("rtn_dump_d.out", ofstream::out); // Dump dynamic infos about routines in runtime



// This struct is used to record informations about a executed instruction
typedef struct InsInfo
{
	ADDRINT _address;	// instruction address
	string _macCode;	// instruction machine code
	string _disasm;		// instruction disassembly code
	UINT32 _size;	// instruction size
	struct InsInfo * _next;	// point to next instruction
} INS_INFO;

// This struct is used to record informations of the application's routines
typedef struct RtnInfo
{
	string _name;	// routine's name
	string _image;	// image the routine loaded from
	ADDRINT _address;	// routine's entyr address
	RTN _rtn;		// Pin object of the routine
	UINT64 _rtnCount;	// the number of the routines in the app
	UINT64 _iCount;		// the number of instructions in the routine
	struct RtnInfo * _next;	// point to next routine
	INS_INFO * _firstIns; // point to the first instruction in the routine
} RTN_INFO;

INS_INFO *InsList = NULL;
RTN_INFO *RtnList = NULL;

// Count instructions or routines
VOID PIN_FAST_ANALYSIS_CALL docount(UINT64 * counter)
{
	(*counter)++;
}

//  When a instruction is executed, dump the relative infos: ip, opcode, disassembly code, 
// Trick... convert void* to string --  string *s1 = static_cast<string *>(s2);  // s2 is void *
VOID PIN_FAST_ANALYSIS_CALL  dump(void *ip, UINT32 size, void * disasm)
{
	INS_INFO * inf = new INS_INFO;

	stringstream op;
	UINT8 *OpBytes = new UINT8[size];
	if (PIN_SafeCopy(OpBytes, ip, size) != size)
	{
		/*op = "Unable to retrive mac code...";*/
	}
	else
	{
		for (UINT32 i = 0; i < size; i++)
		{
			op << setfill('0') << setw(2) << std::hex << int(OpBytes[i]);
		}
	}
	delete OpBytes;

	inf->_address = (ADDRINT)ip;
	inf->_disasm = *(static_cast<string *>(disasm));
	inf->_size = size;
	inf->_macCode = op.str();

	inf->_next = InsList;
	InsList = inf;

}

VOID  PIN_FAST_ANALYSIS_CALL insDump(void *ip, UINT32 size, void * disasm, void *listPtr)
{
	INS_INFO * inf = new INS_INFO;
	INS_INFO ** ptr = (INS_INFO **)listPtr;

	stringstream op;
	UINT8 *OpBytes = new UINT8[size];
	if (PIN_SafeCopy(OpBytes, ip, size) != size)
	{
		/*op = "Unable to retrive mac code...";*/
	}
	else
	{
		for (UINT32 i = 0; i < size; i++)
		{
			op << setfill('0') << setw(2) << std::hex << int(OpBytes[i]);
		}
	}
	delete OpBytes;

	inf->_address = (ADDRINT)ip;
	inf->_disasm = *(static_cast<string *>(disasm));
	inf->_size = size;
	inf->_macCode = op.str();

	inf->_next = *ptr;
	*ptr = inf;

}

// Strip image path and return image name
const char * StripPath(const char * path)
{
	const char * name = strrchr(path, '\\');
	if (name)
		return name + 1;
	else
		return path;
}

VOID Trace(TRACE trace, VOID *v)
{
	// Visit every BBL in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		// Visit every instruction in the bbl, record its infos
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			INS_InsertCall(
				ins, IPOINT_BEFORE, (AFUNPTR)dump,
				IARG_FAST_ANALYSIS_CALL,
				IARG_ADDRINT, INS_Address(ins),
				//IARG_PTR, new string(INS_Mnemonic(ins)), 
				IARG_UINT32, INS_Size(ins),
				IARG_PTR, new string(INS_Disassemble(ins)),
				IARG_END);
		}
	}

}

// Instrument in routine, record static routine infos
//VOID Routine(RTN rtn, VOID *v)
//{
//
//	RTN_INFO *ri = new RTN_INFO;
//
//	// the RTN goes away when the image is unloaded, so save it when it is called
//	// Static routine infos, the routine may not be executed in runtime
//	ri->_name = RTN_Name(rtn);
//	ri->_image = StripPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
//	ri->_address = RTN_Address(rtn);
//	ri->_iCount = 0;
//	ri->_rtnCount = 0;
//
//	//ri->_iCount = RTN_NumIns(rtn);
//
//	ri->_next = RtnList;
//	RtnList = ri;
//
//	RTN_Open(rtn);
//
//	if (!RTN_IsArtificial(rtn) && !RTN_IsDynamic(rtn))
//	{
//		// Insert a call at the entry point of a routine to increment the call count
//		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(ri->_rtnCount), IARG_END);
//
//		// For each instruction of the routine
//		for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
//		{
//			// Insert a call to increment the instruction counter for the rtn
//			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(ri->_iCount), IARG_END);
//
//		}
//	}
//
//
//	RTN_Close(rtn);
//
//
//}

VOID ImageLoad(IMG img, VOID *v)
{
	

	// When a image is loaded, find all routines in it
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{
			// Initialize rtn info struct
			RTN_INFO *ri = new RTN_INFO;

			// the RTN goes away when the image is unloaded, so save it when it is called
			// Static routine infos, the routine may not be executed in runtime
			ri->_name = RTN_Name(rtn);
			ri->_image = StripPath(IMG_Name(img).c_str());
			ri->_address = RTN_Address(rtn);
			ri->_iCount = 0;
			ri->_rtnCount = 0;
			ri->_firstIns = NULL;

			ri->_next = RtnList;
			RtnList = ri;

			RTN_Open(rtn);

			if (!RTN_IsArtificial(rtn) && !RTN_IsDynamic(rtn)) // If the rtn is not generated by pin
			{
				// Insert a call at the entry point of a routine to increment the call count
				RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(ri->_rtnCount), IARG_END);

				// For each instruction of the routine, dump the infomation when it executed
				//for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
				//{
				//	// Insert a call to increment the instruction counter for the rtn
				//	//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_FAST_ANALYSIS_CALL, IARG_PTR, &(ri->_iCount), IARG_END);

				//	// Record the ins's info 
				//	INS_InsertCall(ins, IPOINT_BEFORE, 
				//		(AFUNPTR)insDump, IARG_FAST_ANALYSIS_CALL,
				//		IARG_ADDRINT, INS_Address(ins), 
				//		IARG_UINT32, INS_Size(ins),
				//		IARG_PTR, new string(INS_Disassemble(ins)),
				//		IARG_PTR, &(ri->_firstIns),
				//		IARG_END);
				//}
			}


			RTN_Close(rtn);


		}
	}
}
// Pin calls this function every time a new instruction is encountered
//VOID Instruction(INS ins, VOID *v)
//{
//
//	INS_InsertCall(
//		ins, IPOINT_BEFORE, (AFUNPTR)dump,
//		IARG_ADDRINT, INS_Address(ins),
//		//IARG_PTR, new string(INS_Mnemonic(ins)), 
//		IARG_UINT32, INS_Size(ins),
//		IARG_PTR, new string(INS_Disassemble(ins)),
//		IARG_END);
//}

//KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
//	"o", "dump.out", "specify output file name");

VOID OutputInsInfo()
{
	SetAddress0x(true);
	//// Dump instruction infos of the application
	OutFile << left << setw(12) << "address" << "  "
		<< setw(16) << "machine code" << "  "
		<< setw(4) << "size" << "  "
		<< "disassemble" << endl;

	for (INS_INFO * inf = InsList; inf; inf = inf->_next)
	{
		OutFile << left << setw(12) << hex << StringFromAddrint(inf->_address) << "  "
			<< setw(16) << inf->_macCode << dec << "  "
			<< setw(4) << inf->_size << "  "
			<< inf->_disasm << endl;
	}

	delete InsList;
	if (OutFile.is_open()) OutFile.close();

}

VOID OutputRtnInfo()
{
	SetAddress0x(true);

	// Dump routine infos of the application
	RtnStaticOutFile << left << setw(30) << "Procedure" << "  "
		<< setw(25) << "Image" << "  "
		<< setw(18) << "Address" << "  "
		<< setw(12) << "Calls" << "  "
		<< setw(12) << "InsCount" << endl;
	for (RTN_INFO *ri = RtnList; ri; ri = ri->_next)
	{
		if (ri->_rtnCount > 0) // Ensure the routine is not empty and executed in runtime
		{
			RtnStaticOutFile << left << setw(30) << ri->_name << "  "
				<< setw(25) << ri->_image << "  "
				<< setw(18) << StringFromAddrint(ri->_address) << "  "
				<< setw(12) << ri->_rtnCount << "  "
				<< setw(12) << ri->_iCount << endl << endl;

			for (INS_INFO * inf = ri->_firstIns; inf; inf = inf->_next)
			{
				RtnStaticOutFile << left << setw(12) << hex << StringFromAddrint(inf->_address) << "  "
					<< setw(16) << inf->_macCode << dec << "  "
					<< setw(4) << inf->_size << "  "
					<< inf->_disasm << endl;
			}
		}
	}

	delete RtnList->_firstIns;
	delete RtnList;
	if (RtnStaticOutFile.is_open()) RtnStaticOutFile.close();

}
// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
	//SetAddress0x(true);

	//// Dump routine infos of the application
	//RtnStaticOutFile << left << setw(30) << "Procedure" << "  "
	//	<< setw(25) << "Image" << "  "
	//	<< setw(18) << "Address" << "  "
	//	<< setw(12) << "Calls" << "  "
	//	<< setw(12) << "InsCount" << endl;
	//for (RTN_INFO *ri = RtnList; ri; ri = ri->_next)
	//{
	//	if (ri->_firstIns) // Ensure the routine is not empty
	//	{
	//		RtnStaticOutFile << left << setw(30) << ri->_name << "  "
	//			<< setw(25) << ri->_image << "  "
	//			<< setw(18) << StringFromAddrint(ri->_address) << "  "
	//			<< setw(12) << ri->_rtnCount << "  "
	//			<< setw(12) << ri->_iCount << endl << endl;

	//		for (INS_INFO * inf = ri->_firstIns; inf; inf = inf->_next)
	//		{
	//			RtnStaticOutFile << left << setw(12) << hex << StringFromAddrint(inf->_address) << "  "
	//				<< setw(16) << inf->_macCode << dec << "  "
	//				<< setw(4) << inf->_size << "  "
	//				<< inf->_disasm << endl;
	//		}
	//	}
	//}
	////// Dump instruction infos of the application
	//OutFile << left << setw(12) << "address" << "  "
	//	<< setw(16) << "machine code" << "  "
	//	<< setw(4) << "size" << "  "
	//	<< "disassemble" << endl;

	//for (INS_INFO * inf = InsList; inf; inf = inf->_next)
	//{
	//	OutFile << left << setw(12) << hex << StringFromAddrint(inf->_address) << "  "
	//		<< setw(16) << inf->_macCode << dec << "  "
	//		<< setw(4) << inf->_size << "  "
	//		<< inf->_disasm << endl;
	//}

	//delete RtnList;
	//delete InsList;

	//if (OutFile.is_open()) OutFile.close();
	//if (RtnStaticOutFile.is_open()) RtnStaticOutFile.close();

	//OutputInsInfo();
	OutputRtnInfo();

	cout << "\napplication exited!" << endl;

}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	cerr << "This tool counts the number of dynamic instructions executed" << endl;
	cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char * argv[])
{
	// Initialize symbol table code, needed for rtn instrumentation
	//PIN_InitSymbolsAlt(EXPORT_SYMBOLS);
	PIN_InitSymbols();

	// Initialize pin
	if (PIN_Init(argc, argv)) return Usage();

	// Register ImageLoad to be called to instrument image
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// Register Routine to be called to instrument routine
	//RTN_AddInstrumentFunction(Routine, 0);

	// Register Instruction to be called to instrument instructions
	//INS_AddInstrumentFunction(Instruction, 0);

	//TRACE_AddInstrumentFunction(Trace, 0);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}