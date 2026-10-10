// Linear-sweep decode test: how many words of .text does this processor fail to decode,
// and which opcode patterns are they? Run headless after import with -noanalysis.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.util.*;

public class ProbeDecode extends GhidraScript {
    @Override
    public void run() throws Exception {
        MemoryBlock text = currentProgram.getMemory().getBlock(".text");
        PseudoDisassembler dis = new PseudoDisassembler(currentProgram);
        long total = 0, bad = 0;
        Map<String, Integer> kinds = new TreeMap<>();
        Map<String, String> example = new HashMap<>();
        for (Address a = text.getStart(); a.compareTo(text.getEnd()) < 0; a = a.add(4)) {
            int w = currentProgram.getMemory().getInt(a);
            total++;
            PseudoInstruction ins = null;
            try { ins = dis.disassemble(a); } catch (Exception e) { ins = null; }
            if (ins == null) {
                bad++;
                int op = (w >>> 26) & 0x3f, fn = w & 0x3f, rs = (w >>> 21) & 0x1f;
                String k = op == 0 ? String.format("SPECIAL fn=%02x", fn)
                         : op == 0x1c ? String.format("MMI fn=%02x", fn)
                         : op == 0x12 ? String.format("COP2 rs=%02x", rs)
                         : op == 0x11 ? String.format("COP1 rs=%02x fn=%02x", rs, fn)
                         : String.format("op=%02x", op);
                kinds.merge(k, 1, Integer::sum);
                example.putIfAbsent(k, a + ":" + String.format("%08x", w));
            }
        }
        println("language: " + currentProgram.getLanguageID() + "  compiler: " + currentProgram.getCompilerSpec().getCompilerSpecID());
        println("words: " + total + "  undecodable: " + bad);
        List<Map.Entry<String, Integer>> l = new ArrayList<>(kinds.entrySet());
        l.sort((x, y) -> y.getValue() - x.getValue());
        for (int i = 0; i < Math.min(30, l.size()); i++)
            println(String.format("  %-22s x%-6d e.g. %s", l.get(i).getKey(), l.get(i).getValue(), example.get(l.get(i).getKey())));
    }
}
