package wowemulation;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Detects World of Warcraft client binaries during Ghidra auto-analysis.
 *
 * Detection scans .rdata for the ".?AVCObject@@" RTTI type_info string,
 * present in all known WoW builds (3.3.5a through 1.15.x). On detection,
 * sets program properties and counts RTTI entries.
 *
 * The detailed analysis (RTTI chain walking, Lua API resolution, symbol
 * import) is handled by the Python scripts in ghidra_scripts/. Run them
 * from Script Manager after this analyzer completes.
 */
public class WowBinaryAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "WoW Binary Detector";
	private static final String DESCRIPTION =
		"Detects WoW client binaries via RTTI signatures and counts " +
		"type_info entries. Run the bundled Python scripts from Script " +
		"Manager for full RTTI analysis, Lua API resolution, and " +
		"symbol management.";

	private static final String PROPERTY_LIST = "WoW Analysis";

	// CObject is the root of WoW's game object hierarchy.
	private static final byte[] COBJECT_SIG = ".?AVCObject@@".getBytes();

	// RTTI type_info names all start with this prefix.
	private static final byte[] AV_PREFIX = ".?AV".getBytes();

	public WowBinaryAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		MemoryBlock rdata = findReadOnlyDataBlock(program);
		if (rdata == null) {
			return false;
		}
		try {
			Memory memory = program.getMemory();
			Address found = memory.findBytes(
				rdata.getStart(), rdata.getEnd(),
				COBJECT_SIG, null, true, TaskMonitor.DUMMY);
			return found != null;
		}
		catch (Exception e) {
			return false;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set,
			TaskMonitor monitor, MessageLog log) throws CancelledException {

		MemoryBlock rdata = findReadOnlyDataBlock(program);
		if (rdata == null) {
			log.appendMsg(NAME, "No read-only data section found");
			return false;
		}

		Memory memory = program.getMemory();
		Address start = rdata.getStart();
		Address end = rdata.getEnd();

		// Count RTTI type_info entries.
		monitor.setMessage("WoW: counting RTTI type_info entries...");
		int rttiCount = 0;
		Address addr = start;
		while (addr != null && addr.compareTo(end) < 0) {
			monitor.checkCancelled();
			addr = memory.findBytes(addr, end, AV_PREFIX, null, true, monitor);
			if (addr != null) {
				rttiCount++;
				addr = addr.add(1);
			}
		}

		// Set program properties.
		var options = program.getOptions(PROPERTY_LIST);
		options.setBoolean("Detected", true);
		options.setInt("RTTI Entry Count", rttiCount);
		options.setString("Executable", program.getExecutablePath());

		log.appendMsg(NAME,
			"WoW binary detected: " + rttiCount + " RTTI type_info entries");
		monitor.setMessage(
			"WoW: detected, " + rttiCount + " RTTI entries");

		return true;
	}

	private MemoryBlock findReadOnlyDataBlock(Program program) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			String name = block.getName();
			if (".rdata".equals(name) || ".rodata".equals(name)) {
				return block;
			}
		}
		return null;
	}
}
