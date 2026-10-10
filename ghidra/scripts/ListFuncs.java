// Dump every function's entry, body min/max and name as TSV (argument: output path).
//@category crta
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.Function;

public class ListFuncs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintWriter out = new PrintWriter(args[0])) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                StringBuilder sb = new StringBuilder();
                for (AddressRange r : f.getBody()) {
                    if (sb.length() > 0) sb.append(',');
                    sb.append(r.getMinAddress().toString()).append('-').append(r.getMaxAddress().toString());
                }
                out.println(f.getEntryPoint().toString() + "\t" + f.getName() + "\t" + sb);
            }
        }
    }
}
