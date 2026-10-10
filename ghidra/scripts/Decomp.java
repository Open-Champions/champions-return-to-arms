// Decompile the functions containing the given addresses and write C to a file.
// Usage (headless): -postScript Decomp.java /abs/out.c 199214 13af44 ...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.util.LinkedHashSet;
import java.util.Set;

public class Decomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        Set<Function> todo = new LinkedHashSet<>();
        for (int i = 1; i < args.length; i++) {
            Address a = toAddr(Long.parseLong(args[i], 16));
            Function f = getFunctionContaining(a);
            if (f == null) { disassemble(a); f = createFunction(a, null); }
            if (f == null) { println("no function at " + a); continue; }
            todo.add(f);
        }
        try (PrintWriter out = new PrintWriter(args[0])) {
            for (Function f : todo) {
                DecompileResults r = dec.decompileFunction(f, 120, monitor);
                out.println("// ===== " + f.getName() + " @ " + f.getEntryPoint() + "  size=" + f.getBody().getNumAddresses()
                        + (f.getComment() != null ? "  // " + f.getComment() : ""));
                if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
                else out.println("// decompile failed: " + r.getErrorMessage());
            }
        }
        println("decompiled " + todo.size() + " functions -> " + args[0]);
    }
}
