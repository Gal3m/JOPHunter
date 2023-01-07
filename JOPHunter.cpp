    #include <fstream>
    #include <iomanip>
    #include <iostream>
    #include <string.h>
    #include <string>
    #include <sstream>
    #include <stdio.h>
    #include <stdlib.h>
    #include "pin.H"
    #include "pin_isa.H"
    #include <set>
    #include <list>
    
    
    ofstream OutFile;
    const unsigned int MAX_LEGIT_INSTRUCTION_LOG_SIZE = 5;
    const ADDRINT invalid_ptr = 0xFFFFFFFF;
    std::list<std::string> legitInstructions;
    
    static UINT32 meet_crossjump = 0;
    static string _lib_from = "";
    static string _lib_target = ""; 
    static ADDRINT _addr_from = 0;
    static ADDRINT _addr_target = 0; 

    const unsigned int MAX_LEGIT_INSTRUCTION_PER_GADGET = 7;
    const unsigned int MAX_LEGIT_INSTRUCTION_PER_DELAYGADGET = 20;
    const unsigned int MAX_LEGIT_CONSECUTIVE_GADGETS = 10;
    
    typedef struct Signature
    {
        string _imagename;
        string _gadgettype;
        ADDRINT _physical_startgadget_address;
        ADDRINT _physical_endgadget_address;
        string _kind;
        INT32 _numberof_valid_ins;
        string _source_reg;
        string _jump_reg;
        string _syscall_index;
    
        struct Signature * _next;
    
    } ActiveSignature;
    
    // Linked list of Loaded Trampoline.
    ActiveSignature * ACSList = 0;
    //-----------------------------------------------------------------------------------------
    typedef struct ImageInfo
    {
        string _imagename;
        ADDRINT _baseaddress;
    
        struct ImageInfo * _next;
    
    } LoadedImagesInfo;
    
    // Linked list of Loaded Images Information.
    LoadedImagesInfo * LIIList = 0;
    //-----------------------------------------------------------------------------------------
    typedef struct SignatureInfo
    {
        string _imagename;
        string _gadgettype;
        ADDRINT _startgadget_offset;
        ADDRINT _endgadget_offset;
        string _kind;
        INT32 _numberof_valid_ins;
        string _source_reg;
        string _jump_reg;
        string _syscall_index;
    
        struct SignatureInfo * _next;
    
    } AllSignatureInfo;
    
    AllSignatureInfo * ASList = 0;
    
    int ReadSignatures() {
    	string line, errorreport;
    	string var_imagename, var_gadgettype, var_startgadget_offset, var_endgadget_offset, var_kind, var_numberof_valid_ins, var_source_reg,  var_jump_reg, var_syscall_index;
    	int pos1,pos2,pos3,pos4,pos5,pos6,pos7,pos8;
    	ifstream settingsfile ("/home/ali/Desktop/pin/source/tools/mythesis/JOPHunter_signatures.txt");
    	if (!settingsfile.is_open()) {
    				return 0;
    	}
    
    	while (settingsfile.good())
    	 {
    		getline (settingsfile,line);
    
    		if(line.length() == 0) continue;
    
    		if(line[0] == '#') continue; //skip comments
    
    		pos1 = line.find_first_of(':');
    	        pos2 = line.find_first_of(';');
    		pos3 = line.find_first_of('@');
    		pos4 = line.find_first_of('!');
    		pos5 = line.find_first_of('$');
    		pos6 = line.find_first_of('%');
    		pos7 = line.find_first_of('^');
    		pos8 = line.find_first_of('&');
    
    		if(pos1 == -1) continue;
    		if(pos2 == -1) continue;
    		if(pos3 == -1) continue;
    		if(pos4 == -1) continue;
    		if(pos5 == -1) continue;
    		if(pos6 == -1) continue;
    		if(pos7 == -1) continue;
    		if(pos8 == -1) continue;
    
    
     	        var_imagename = line.substr(0,pos1);
    	        var_gadgettype = line.substr(pos1+1,(pos2-pos1-1));
                    var_startgadget_offset = line.substr(pos2+1,10);
    	        var_endgadget_offset = line.substr(pos3+1,10);
    	        var_kind = line.substr(pos4+1,10);
                    var_numberof_valid_ins = line.substr(pos5+1,1);
    	        var_source_reg = line.substr(pos6+1,3);
                    var_jump_reg = line.substr(pos7+1,3);
                    var_syscall_index = line.substr(pos8+1,2);
    
    
    
     		AllSignatureInfo * rc = new AllSignatureInfo;
    
    	 	rc->_imagename = var_imagename;
     	        rc->_gadgettype = var_gadgettype;
    	        rc->_startgadget_offset = AddrintFromString(var_startgadget_offset);
    	        rc->_endgadget_offset = AddrintFromString(var_endgadget_offset);
    	        rc->_kind = var_kind;
    		rc->_numberof_valid_ins = strtoul(var_numberof_valid_ins.c_str(),NULL,10);
    	        rc->_source_reg = var_source_reg;
         		rc->_jump_reg = var_jump_reg;
         		rc->_syscall_index = var_syscall_index;
    
    	        // Add to list of routines
    		rc->_next = ASList;
    		ASList = rc;
    	}
    
    	settingsfile.close();
    return 1;
    }
    const char * StripPath(const char * path)
    {
        const char * file = strrchr(path,'/');
        if (file)
            return file+1;
        else
            return path;
    }
    //------------------------------------------------------------------------------------------
    VOID ImageLoad(IMG img, VOID *v)
    {
        LoadedImagesInfo * rc = new LoadedImagesInfo;
    
        rc->_imagename = StripPath(IMG_Name(img).c_str());
        rc->_baseaddress = IMG_LowAddress(img);
    
    	for (AllSignatureInfo * rc2 = ASList; rc2; rc2 = rc2->_next)
    	    {
    	        if (rc->_imagename == rc2->_imagename)
    		{
    	                ActiveSignature * rc3 = new ActiveSignature;
    
        		        rc3->_imagename = rc2->_imagename;
    		        rc3->_gadgettype = rc2->_gadgettype;
    		        rc3->_physical_startgadget_address = (rc->_baseaddress + rc2->_startgadget_offset);
    		        rc3->_physical_endgadget_address = (rc->_baseaddress + rc2->_endgadget_offset);
    		        rc3->_kind = rc2->_kind;
    		        rc3->_numberof_valid_ins = rc2->_numberof_valid_ins;
     		        rc3->_source_reg = rc2->_source_reg;
    		        rc3->_jump_reg = rc2->_jump_reg;
     		        rc3->_syscall_index = rc2->_syscall_index;
    
    			rc3->_next = ACSList;
    			ACSList = rc3;
    		}
    	    }
    
        rc->_next = LIIList;
        LIIList = rc;
    }
    //-----------------------------------------------------------------------------------------
    int FillActiveSignature() {
      for (LoadedImagesInfo * rc = LIIList; rc; rc = rc->_next)
        {
    	for (AllSignatureInfo * rc2 = ASList; rc2; rc2 = rc2->_next)
    	    {
    	        if (rc->_imagename == rc2->_imagename)
    		{
    	                ActiveSignature * rc3 = new ActiveSignature;
    
        		        rc3->_imagename = rc2->_imagename;
    		        rc3->_gadgettype = rc2->_gadgettype;
    		        rc3->_physical_startgadget_address = (rc->_baseaddress + rc2->_startgadget_offset);
    		        rc3->_physical_endgadget_address = (rc->_baseaddress + rc2->_endgadget_offset);
    		        rc3->_kind = rc2->_kind;
    		        rc3->_numberof_valid_ins = rc2->_numberof_valid_ins;
     		        rc3->_source_reg = rc2->_source_reg;
    		        rc3->_jump_reg = rc2->_jump_reg;
     		        rc3->_syscall_index = rc2->_syscall_index;
    
    			rc3->_next = ACSList;
    			ACSList = rc3;
    		}
    	    }
        }
    
    return 1;
    }
    //-----------------------------------------------------------------------------------------
    bool isUnknownAddress(ADDRINT address){
        for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
           {
            for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    	   {
    	    if(address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
    	      {
    		 return false;
    	      }
    	   }		
    	}
    return true;
    }
    //-----------------------------------------------------------------------------------------
    std::string getModule(ADDRINT address){
       for(IMG img=APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
          {
           for(SEC sec=IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
              {
               if (address >= SEC_Address(sec) && address < SEC_Address(sec) + SEC_Size(sec))
                 {
                  return StripPath(IMG_Name(img).c_str());
                 }
              }
          }
    return "";
    }
    //------------------------------------------------------------------------------------------
    VOID  Check_CrossLibraryBoundary(std::string insfrom, ADDRINT from, ADDRINT target)
      {
         if (meet_crossjump == 0)
          {
             string lib_from = getModule(from);
             string lib_target = getModule(target);
	   
             if (lib_from != lib_target)
              {
                meet_crossjump = 1;
                _lib_from = lib_from;
 	        _lib_target = lib_target;
		_addr_from = from;
		_addr_target = target;
              } 
          }
         else if (meet_crossjump > 0)
          {
            meet_crossjump = 0;            
            OutFile << "Detecting JOP Attack using Cross Library Boundary Check. Source:"<<hex<<_addr_from<<" Target:"<<hex<<_addr_target<< endl;
    	    OutFile << "insTail Target: "<<insfrom<<endl;
             
            _lib_from = "";
 	    _lib_target = "";
	    _addr_from = 0;
	    _addr_target = 0;
            //PIN_ExitApplication(0);
          }
    }
    //------------------------------------------------------------------------------------------
    VOID Check_2ComplementINSourceRegister(std::string src_reg, CONTEXT * ctxt)
    {
    ADDRINT src_reg_value = 0; 
    ADDRINT entry_offset = 0;
    
    	 if (src_reg == "eax")
                     src_reg_value = PIN_GetContextReg(ctxt, REG_EAX);
    	 else if (src_reg == "ebx")
    	         src_reg_value = PIN_GetContextReg(ctxt, REG_EBX);
    	 else if (src_reg == "ecx")
                     src_reg_value = PIN_GetContextReg(ctxt, REG_ECX);
    	 else if (src_reg == "edx")
                     src_reg_value = PIN_GetContextReg(ctxt, REG_EDX);
    	 else if (src_reg == "esi")
                     src_reg_value = PIN_GetContextReg(ctxt, REG_ESI);
    	 else if (src_reg == "edi")
                     src_reg_value = PIN_GetContextReg(ctxt, REG_EDI);
    	 else if (src_reg == "ebp")
                     src_reg_value = PIN_GetContextReg(ctxt, REG_EBP);

         entry_offset = (src_reg_value ^ 0xffffffff) + 1;
    	 if (entry_offset >=4 && entry_offset<=20)
    	   {
    		OutFile << "Detecting JOP Attack using intended Dispatcher Gadget Signature,  value of source register ["<<src_reg<<"] is "<<hex<<entry_offset<<endl;
    	        //PIN_ExitApplication(0);
               }
    }
    //------------------------------------------------------------------------------------------
    std::string dump_ExecutedInstruction(INS ins, ADDRINT address)
    {
    std::stringstream ss;
    ss << "0x" << setfill('0') << setw(8) << uppercase << hex << address << "|" << INS_Disassemble(ins);
    
      if(INS_IsIndirectBranchOrCall(ins))
        {      
           	if( INS_IsCall(ins) && !INS_HasFallThrough(ins) && !INS_IsHalt(ins) && !INS_IsRet(ins))
               ss << ";" <<"IndirectCall" ;
            else if( !INS_IsCall(ins) && !INS_HasFallThrough(ins) && !INS_IsHalt(ins) && !INS_IsRet(ins))
                   ss << ";" <<"IndirectJump";
           else if (INS_IsRet(ins))
    	  {
    	    ss << ";" <<"Ret";
    	  }
        }
       else
         ss << ";" <<"Null";
    
    return ss.str();
    }
    //------------------------------------------------------------------------------------------
    VOID Check_RegisterEAX(string _value, CONTEXT * ctxt)
    {
       ADDRINT org_value = AddrintFromString(_value);
       ADDRINT src_reg_value = 0; 
       src_reg_value = PIN_GetContextReg(ctxt, REG_EAX);
    if ((src_reg_value != org_value))
       {
    	OutFile << "Detecting JOP Attack using SetEAXandTRAPtoKernel Gadget Signature, EAX value should be ["<<hex<<org_value<<"] but, Current EAX value is ["<<hex<<src_reg_value<<"]"<<endl;
    	        //PIN_ExitApplication(0);
       }
    }
    //------------------------------------------------------------------------------------------
    VOID Trace(TRACE trace, VOID *v)
    {
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
          INS insTail =  BBL_InsTail(bbl);
    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
          if (meet_crossjump == 0)
            {
             if(INS_IsIndirectBranchOrCall(insTail))
    	  {
               if (INS_IsBranch(insTail))
                {
                  RTN rtn = TRACE_Rtn(trace);
                  if(RTN_Valid(rtn) && ".plt" != SEC_Name(RTN_Sec(rtn)))
                   {
                     INS_InsertCall(insTail, IPOINT_TAKEN_BRANCH, (AFUNPTR)Check_CrossLibraryBoundary,
                      IARG_PTR, new string(INS_Disassemble(insTail)),
                      IARG_INST_PTR,
                      IARG_BRANCH_TARGET_ADDR,
                      IARG_END);
                   }
                }
    	  }
            }
            else if (meet_crossjump == 1 && INS_IsIndirectBranchOrCall(insTail))
    	  {
                     INS_InsertCall(insTail, IPOINT_TAKEN_BRANCH, (AFUNPTR)Check_CrossLibraryBoundary,
                      IARG_PTR, new string(INS_Disassemble(insTail)),
                      IARG_INST_PTR,
                      IARG_BRANCH_TARGET_ADDR,
                      IARG_END);
    	  }
	    else if (meet_crossjump == 1 && INS_IsDirectCall(insTail))
	  {
            meet_crossjump = 0;
            _lib_from = "";
 	    _lib_target = "";
	    _addr_from = 0;
	    _addr_target = 0;
	  }
    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
           if (INS_IsIndirectBranchOrCall(insTail)||INS_IsRet(insTail))
               {//0
    	         ADDRINT tail_address = INS_Address(insTail);              
                 std::string ModuleName = getModule(tail_address);
                 for (ActiveSignature * rc3 = ACSList; rc3; rc3 = rc3->_next)
                    {//1               
                       if(ModuleName == rc3->_imagename /*&& tail_address == rc3->_physical_endgadget_address*/)
    	    	     {//2
    			 std::size_t found_unintended = rc3->_kind.find("unintended");
    		       	 std::size_t found_intended = rc3->_kind.find("**intended");
    			 INT32 numberof_ins = 0;
    			 for(INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins=INS_Next(ins))
                  		   {//3
     			     ADDRINT ins_address = INS_Address(ins); 
                             numberof_ins++;
    			     if (ins_address == rc3->_physical_startgadget_address && found_unintended!=std::string::npos)
    				{//4
    				  OutFile << "Unintended "<< rc3->_gadgettype <<" Gadget for JOP attack Detected at Address 0x"<<  uppercase << hex << ins_address <<", " << "[INS] " << INS_Disassemble(ins) <<endl;
                                    }//4
                                   else if (ins_address == rc3->_physical_startgadget_address && found_intended!=std::string::npos)
    				      {//5
    					if (rc3->_gadgettype == "Dispatcher")
    					   {//6
                                                  INS_InsertCall(insTail, IPOINT_TAKEN_BRANCH, (AFUNPTR)Check_2ComplementINSourceRegister,
                   				  		   IARG_PTR, new string(rc3->_source_reg),
    					                 	   IARG_CONTEXT,             
	    					                   IARG_END);
    					   }//6
     				          else if (rc3->_gadgettype == "Trampoline" || rc3->_gadgettype == "Initializer" || rc3->_gadgettype == "KernelTrap")
    						  {//7
    						    if (numberof_ins < (rc3->_numberof_valid_ins+1))
    						       {//8
     							   OutFile << "intended "<< rc3->_gadgettype <<" Gadget for JOP attack Detected at Address 0x"<<uppercase << hex << ins_address <<", " << "[INS] " << INS_Disassemble(ins) <<endl;
    	        					   //PIN_ExitApplication(0);
    						       }//8	
    						  }//7
    					  else if (rc3->_gadgettype == "SetEAXandTRAPtoKernel")
    						  {//9  
                                                         INS_InsertCall(insTail, IPOINT_TAKEN_BRANCH, (AFUNPTR)Check_RegisterEAX,
    							      IARG_PTR, new string(rc3->_syscall_index.c_str()),
    					                      IARG_CONTEXT,             
    					                      IARG_END);
    						  }//9

    				      }//5
    
    		               }//3
    		    }//2
    	     }//1
          }//0
    //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    }
    }
    //------------------------------------------------------------------------------------------
    KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool","o", "JOPHunter.out", "specify output file name");
    
    // This function is called when the application exits
    VOID Fini(INT32 code, VOID *v)
    {
        OutFile << setw(23) <<"-------------- Loaded Images Information ----------------------"<<  endl;
        for (LoadedImagesInfo * rc = LIIList; rc; rc = rc->_next)
        {
           OutFile << setw(23) << rc->_imagename << " "
           << setw(20) << hex << rc->_baseaddress <<  endl;
        }
        OutFile << setw(23) <<"---------------- Active Signatures --------------------------"<<  endl;
        for (ActiveSignature * rc3 = ACSList; rc3; rc3 = rc3->_next)
        {
    OutFile << setw(23) << rc3->_imagename << " "
             << setw(10)  << hex << rc3->_gadgettype << " "
             << setw(10)  << hex << rc3->_physical_startgadget_address << ""
    	 << setw(10)  << hex << rc3->_physical_endgadget_address << " "
    	 << setw(10)  << rc3->_kind << " "
    	 << setw(10)  << rc3->_numberof_valid_ins << " "
    	 << setw(10)  << rc3->_source_reg << " "
    	 << setw(10)  << rc3->_jump_reg << " "
    	 << setw(10)  << rc3->_syscall_index << endl;
        }
     OutFile.close();
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
    /* Main   su                                                             */
    /* ===================================================================== */
    /* argc, argv are the entire command line: pin -t <toolname> -- ...    */
    /* ===================================================================== */
    
    int main(int argc, char * argv[])
    {
        ReadSignatures();    
        // Initialize pin
        if (PIN_Init(argc, argv)) return Usage();
        PIN_InitSymbols();
    
        OutFile.open(KnobOutputFile.Value().c_str());
    
        // Register Instruction to be called to instrument instructions
        IMG_AddInstrumentFunction(ImageLoad, 0);
        TRACE_AddInstrumentFunction(Trace, 0);
        
    
    
        // Register Fini to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
        
        // Start the program, never returns
        PIN_StartProgram();
        
        return 0;
    }