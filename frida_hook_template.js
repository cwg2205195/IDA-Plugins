function My_hook() {
    this.hookedLibs = {};
}

/**
 * 
 * @param {Object} param 包含成员: mod_name,fun_name,fun_addr,fun_before,fun_after,arch_64
 * 其中 mod_name 为模块名 , arch_64 = true 表示64位平台
 */
My_hook.prototype.hook = function (param) {
    var so_name = param.mod_name,
        fun_name = param.fun_name,
        fn_before = param.fun_before,
        fn_after = param.fun_after,
        fun_addr = param.fun_addr,
        arch_64 = param.arch_64;
    if (so_name == "") {
        send("[+]Hook failed. Empty module name !!!!!!");
        return;
    }
    if (fun_addr == undefined && fun_name == "") {
        send("[+]Hook failed. Wrong address " + address + " or function name: " + fun_name);
        return;
    }
    if ((fn_after != undefined && fn_after instanceof Function == false) ||
        (fn_before != undefined && fn_before instanceof Function == false)) {
        send("[+]Hook failed : wrong hook function type");
        return;
    }
    var base = Module.getBaseAddress(so_name);
    if (base) {
        send("[+]" + so_name + " @ " + base);
        if (fun_addr == undefined)
            fun_addr = Module.getExportByName(so_name, fun_name);
        else
            fun_addr = new NativePointer(parseInt(base) + fun_addr + (arch_64 ? 0 : 1))
        if (fun_addr) {
            send("[+]" + so_name + "->" + fun_name + "@" + fun_addr);
            Interceptor.attach(fun_addr, {
                onEnter: function (args) {
                    send("[+]" + so_name + "->" + fun_name + "@" + fun_addr + " entering...");
                    fn_before(args, this);
                },
                onLeave: function (retval) {
                    fn_after(retval, this);
                    send("[+]" + so_name + "->" + fun_name + "@" + fun_addr + " leavel...");
                }
            });
            if (this.hookedLibs[so_name] == undefined)
                this.hookedLibs[so_name] = {}
            try {
                this.hookedLibs[so_name]["" + fun_addr.toInt32().toString(16)] = fun_name ? fun_name : "sub_" + fun_addr.toInt32().toString(16)
                send(JSON.stringify(this.hookedLibs));
            } catch (error) {
                send(error.toString())
            }
        }
        else {
            send("[+]Hook failed module " + so_name + " function was not found [" + fun_name + "]");
            return;
        }
    }
    else {
        send("[+]Hook failed module " + so_name + " was not found in target memory !!!!!!!!!");
        return;
    }
}

var hooker = new My_hook();
