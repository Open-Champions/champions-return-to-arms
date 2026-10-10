// Apply names.tsv (addr<TAB>name<TAB>note) to the program: functions get created and
// named at code addresses, data addresses get labels. The note becomes a plate comment.
// Usage (headless): -postScript ApplyNames.java /abs/path/names.tsv
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashSet;
import java.util.Set;

public class ApplyNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        String path = getScriptArgs()[0];
        int funcs = 0, labels = 0, created = 0;
        Set<String> used = new HashSet<>();
        try (BufferedReader r = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = r.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] p = line.split("\t");
                if (p.length < 2) continue;
                Address a = toAddr(Long.parseLong(p[0], 16));
                String name = p[1].replaceAll("[^A-Za-z0-9_]", "_");
                if (!used.add(name)) name = name + "_" + p[0];
                String note = p.length > 2 ? p[2] : null;
                if (currentProgram.getMemory().getBlock(a) != null && currentProgram.getMemory().getBlock(a).isExecute()) {
                    Function f = getFunctionAt(a);
                    if (f == null && getFunctionContaining(a) == null) {
                        disassemble(a);
                        f = createFunction(a, name);
                        if (f != null) created++;
                    }
                    if (f != null) {
                        f.setName(name, SourceType.USER_DEFINED);
                        if (note != null) f.setComment(note);
                        funcs++;
                    } else {
                        createLabel(a, name, true, SourceType.USER_DEFINED);
                        labels++;
                    }
                } else {
                    createLabel(a, name, true, SourceType.USER_DEFINED);
                    if (note != null) setEOLComment(a, note);
                    labels++;
                }
            }
        }
        println("named functions: " + funcs + " (created " + created + "), labels: " + labels
                + ", total functions in program: " + currentProgram.getFunctionManager().getFunctionCount());
    }
}
