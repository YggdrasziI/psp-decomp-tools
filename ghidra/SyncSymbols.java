// Name the symbols of the splat symbol files in the current program.
// Run by ghidra_sync.py through analyzeHeadless; arguments: the symbol files,
// then "dry" to report without changing anything.
// @category psp-decomp

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class SyncSymbols extends GhidraScript {

    // name = 0x00012345; // type:func ...
    private static final Pattern LINE =
        Pattern.compile("^\\s*([A-Za-z_.$][\\w.$]*)\\s*=\\s*0x([0-9A-Fa-f]+)\\s*;(.*)$");

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        boolean dry = args.length > 0 && args[args.length - 1].equals("dry");
        int files = dry ? args.length - 1 : args.length;
        // Symbol files hold link addresses (program header 0 at 0); the loader may
        // place the module elsewhere.
        long base = currentProgram.getImageBase().getOffset();
        SymbolTable table = currentProgram.getSymbolTable();
        int same = 0, named = 0, functions = 0, kept = 0, missing = 0;
        List<String> report = new ArrayList<>();

        for (int i = 0; i < files; i++) {
            try (BufferedReader in = new BufferedReader(new FileReader(args[i]))) {
                String line;
                while ((line = in.readLine()) != null) {
                    Matcher m = LINE.matcher(line);
                    if (!m.matches()) {
                        continue;
                    }
                    String name = m.group(1);
                    Address addr = toAddr(base + Long.parseLong(m.group(2), 16));
                    boolean isFunc = m.group(3).contains("type:func");
                    if (currentProgram.getMemory().getBlock(addr) == null) {
                        missing++;
                        report.add("not in memory: " + name + " at " + addr);
                        continue;
                    }
                    Symbol primary = table.getPrimarySymbol(addr);
                    if (primary != null && primary.getName().equals(name)) {
                        same++;
                    } else if (primary != null && primary.getSource() == SourceType.USER_DEFINED) {
                        // A name set by hand in Ghidra is kept: it is a hypothesis to
                        // check, not to overwrite
                        kept++;
                        report.add("kept " + primary.getName() + " at " + addr + " (file: " + name + ")");
                    } else {
                        named++;
                        if (!dry) {
                            Symbol s = table.createLabel(addr, name, SourceType.IMPORTED);
                            s.setPrimary();
                        }
                    }
                    if (isFunc && getFunctionAt(addr) == null) {
                        functions++;
                        if (!dry) {
                            Function f = createFunction(addr, name);
                            if (f == null) {
                                report.add("no function created at " + addr + " (" + name + ")");
                            }
                        }
                    }
                }
            }
        }
        for (String r : report) {
            println(r);
        }
        println(String.format("SyncSymbols%s: %d already named, %d named, %d functions created, "
            + "%d hand names kept, %d outside memory (image base 0x%X)",
            dry ? " (dry run)" : "", same, named, functions, kept, missing, base));
    }
}
