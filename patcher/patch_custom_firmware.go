package main

import "log"

// PatchIsCustomFirmware neutralises GobalVar::isCustomFirmware() by making it
// unconditionally return 0.  The function walks /proc/*/cmdline looking for
// "sshd", "adbd" or "nginx" and shows a scary "Non official firmware" warning
// when any of those processes is found.  Rinkhals legitimately runs such
// processes, so we patch the function to always return 0 (not found).
//
// The patch writes two ARM32 instructions at the function entry point:
//
//	MOV r0, #0   (return value = 0)
//	MOV pc, lr   (return to caller)
//
// Symbol: _ZN8GobalVar16isCustomFirmwareEPKc
// Present on: K3, K3M, K3V2 (absent on KS1/KS1M/K2P – symbol lookup fails silently).
func (p *Patcher) PatchIsCustomFirmware() {
	const sym = "_ZN8GobalVar16isCustomFirmwareEPKc"

	addr, _, err := p.FindSymbol(sym)
	if err != nil {
		log.Printf("isCustomFirmware not present in this binary, skipping patch (%v)", err)
		return
	}

	offset, err := p.AddrToOffset(addr)
	if err != nil {
		log.Printf("Warning: isCustomFirmware symbol found but address could not be mapped: %v", err)
		return
	}

	p.Write32(offset+0, MovRc_Imm(0, 0)) // MOV r0, #0
	p.Write32(offset+4, MovPc_Lr())       // MOV pc, lr

	log.Printf("Patched isCustomFirmware() at VA 0x%x to always return 0", addr)
}
