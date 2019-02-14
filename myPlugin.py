import os
import idaidc
func=GetFunctionAttr(ScreenEA(),FUNCATTR_START)
name=Name(func)
if func!= -1 :
		name=Name(func)
		end=GetFunctionAttr(func,FUNCATTR_END)
		for(inst=func;inst < end ;inst=FindCode(inst,flags)){
			for(target=Rfirst(inst);target!=BADADDR;target=Rnext(inst,target)){
				xref=XrefType();
				if(xref == fl_CN || xref == fl_CF){
					Message("|%s calls %s from 0X%X |\n",name,Name(target),inst);
				}
			}
		}
	 
else :
	Warning("No Function found at localtion %X",ScreenEA())
