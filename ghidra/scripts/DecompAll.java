// Decompile every function to <outdir>/<entry>.c and write <outdir>/index.tsv
// (entry, name, size, callers, callees). Optional second argument: a file of hex entry
// addresses (one per line) to turn into functions first, e.g. virtual functions that
// auto-analysis did not reach.
// Usage (headless): -postScript DecompAll.java /abs/outdir [/abs/extra_entries.txt]
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

public class DecompAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outdir = new File(args[0]);
        outdir.mkdirs();
        int created = 0;
        if (args.length > 1) {
            try (BufferedReader r = new BufferedReader(new FileReader(args[1]))) {
                String line;
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    Address a = toAddr(Long.parseLong(line, 16));
                    if (getFunctionContaining(a) != null) continue;
                    disassemble(a);
                    if (createFunction(a, null) != null) created++;
                }
            }
        }
        println("created " + created + " functions from the extra entry list");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        List<Function> all = new ArrayList<>();
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) all.add(f);
        int ok = 0, failed = 0;
        try (PrintWriter idx = new PrintWriter(new File(outdir, "index.tsv"))) {
            for (Function f : all) {
                if (monitor.isCancelled()) break;
                String ent = f.getEntryPoint().toString();
                TreeSet<String> callees = new TreeSet<>();
                for (Function c : f.getCalledFunctions(monitor)) callees.add(c.getEntryPoint().toString());
                int callers = f.getCallingFunctions(monitor).size();
                long size = f.getBody().getNumAddresses();
                idx.println(ent + "\t" + f.getName() + "\t" + size + "\t" + callers + "\t" + String.join(",", callees));
                DecompileResults r = dec.decompileFunction(f, 90, monitor);
                try (PrintWriter out = new PrintWriter(new File(outdir, ent + ".c"))) {
                    out.println("// " + f.getName() + " @ " + ent + "  size=" + size + "  callers=" + callers
                            + (f.getComment() != null ? "  // " + f.getComment() : ""));
                    if (r.decompileCompleted()) { out.println(r.getDecompiledFunction().getC()); ok++; }
                    else { out.println("// decompile failed: " + r.getErrorMessage()); failed++; }
                }
            }
        }
        println("decompiled " + ok + " functions, " + failed + " failed -> " + outdir);
    }
}
