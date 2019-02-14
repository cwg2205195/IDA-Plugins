# IDA-Plugins
some ida python scripts I wrote for helping RE

1. CntSpecFunCalls.py can count specific function called in current function

2. autoSaveDB.py has bug , should be fixed in the future . It's functionality is automatically save IDB file in 

every some seconds . But it can't work out the way I intend.

3. cmtForXorRegZero.py will make comments in current function where a 'clear register' instruction exists.

such as :'xor eax,eax'

4. getCurFunInsnCnt.py counts how many instructions in current function.

5. getCurLibCalls.py counts how many library function are called in current function.

6. highLightSpeInsn.py will highlight the instruction currently selected.

7. immDataParse.py is not implemented yet.

8. jumpRva.py is used to jump to a RVA in IDB .

9. xrefToFunPath.py is a helpful tool for cross referencing functions. It traverses current function in given

depth to find specific function call , and print out the call path !

Hope my scripts did help you out ! And good luck for RE . 0-o
