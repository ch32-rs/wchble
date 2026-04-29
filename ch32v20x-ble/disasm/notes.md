## globals

EventsArr

## fns

ATT_ConvertUUIDto128

# TMOS

TMOS_ProcessEventRegister

```c
#include <stdint.h>

#define MAX_TASKS  *(uint8_t *)0x8   // 或定义为具体的数值

// 全局变量
uint8_t taskCount = 0;                   // 地址：0x0
void (*tasksArr[])(uint16_t events);     // 地址：0x14

// 函数实现
uint8_t TMOS_ProcessEventRegister(void (*pfnEventProcess)(uint16_t events))
{
    // 加载当前任务计数
    uint8_t currentTaskCount = taskCount;

    // 加载最大任务数
    uint8_t maxTasks = MAX_TASKS;

    // 检查是否超过最大任务数
    if (currentTaskCount >= maxTasks)
    {
        return 255;   // 返回错误码，表示无法注册新任务
    }

    // 注册新的任务处理函数
    tasksArr[currentTaskCount] = pfnEventProcess;

    // 增加任务计数
    taskCount = currentTaskCount + 1;

    // 返回新注册的任务 ID（索引）
    return currentTaskCount;
}
```




---

# real-hardware-verification

Hardware verification of BLE register block layout using a live CH32V208WBU6 board.
**Tool**: `wlink dump <addr> <len>` via WCH-Link.
**lib version**: libwchble.a V1.40 (`d.asm` in this directory).
**Key principle**: process and open questions matter as much as conclusions.

## Setup & Method

1. Flash a minimal BLE example onto CH32V208WBU6 (QFN68).
2. Connect WCH-Link via SWDIO/SWDCLK. Verify with `wlink status`.
3. Halt the chip and dump all four BLE peripheral regions:
   - LLE : `wlink dump 0x40024100 128`
   - BB  : `wlink dump 0x40024200 128`
   - RFEND: `wlink dump 0x40024300 128`
   - AES : `wlink dump 0x40025000 64`
4. Cross-reference dump values against assembly in `d.asm`.

## LLE (0x40024100)

### Raw dump (chip halted, BLE idle/SLEEP state)

```
+0x00  0x00000000  CTRL
+0x04  0x00555555  ?
+0x08  0x8E89BED6  ?
+0x0C  0x00000000  ?
+0x14  0x0000008C  TIMING0 = 140
+0x1C  0x0000006C  STATE_MACHINE = 108
+0x24  0x0000008C  TIMING2 = 140
+0x2C  0x0000003C  TIMING3 = 60
+0x34  0x0000008C  TIMING4 = 140
+0x3C  0x0000003C  TIMING5 = 60
+0x44  0x0000008C  TIMING6 = 140
+0x4C  0x0000006C  TIMING7 = 108
```

### Initial question: what are +0x04 and +0x08?

The reverse-doc (from static analysis only) labeled:
- `+0x04` = STATUS
- `+0x08` = IRQ_STATUS

Hardware reads 0x00555555 and 0x8E89BED6 — these are **BLE protocol constants**:
- 0x555555 = advertising channel CRC init value (BLE spec §2.3)
- 0x8E89BED6 = advertising channel access address (BLE spec §2.1.2)

So the static analysis names were wrong. But the question then becomes: *is +0x08 purely ACCESS_ADDR, or does it serve a dual role?*

### Assembly cross-check: ll_advertise_tx (lle.o)

```asm
# a5 = LLE base (0x40024100), loaded via auipc+mv+lw global pointer pattern
lui  a4, 0x8e89c
addi a4, a4, -298   # a4 = 0x8E89BED6
sw   a4, 8(a5)      # LLE[+0x08] ← ACCESS_ADDR
lui  a4, 0x555
addi a4, a4, 1365   # a4 = 0x00555555
sw   a4, 4(a5)      # LLE[+0x04] ← CRC_INIT
```

Confirms +0x04 = CRC_INIT, +0x08 = ACCESS_ADDR. Both confirmed by hardware values.

### New question: LLE_IRQSubHandler also reads +0x08 — why?

```asm
# LLE_IRQSubHandler
lw   a4, 12(a5)     # read +0x0C (IRQ_MASK)
andi a4, a4, 0x4000 # test bit 14 = IRQ_SEQ_ERROR enable
lw   a4, 8(a5)      # read +0x08  ← same offset as ACCESS_ADDR!
andi a4, a4, 0x4000 # test bit 14 = SEQ_ERROR flag
sw   a3, 8(a5)      # W1C: write 0x4000 to clear

# lle_irq_process
lw   a4, 8(a5)
# tests bits 3 (IRQ_RF_SEQ_END), 2 (IRQ_TX_DONE), 1 (IRQ_RX_DONE)
# writes W1C values back to +0x08
```

**+0x08 is dual-purpose**: TX path writes the full 32-bit ACCESS_ADDR; IRQ path reads/clears lower bits as interrupt status flags (W1C). The hardware register likely holds both simultaneously — upper bits persist as ACCESS_ADDR, lower bits are set by hardware events and cleared by W1C writes.

This is a common pattern in link-layer hardware: the access address register doubles as an event/status register to save address space.

### Unresolved: exact bit boundary between ACCESS_ADDR and IRQ_STATUS

We know bits [3:1] and bit 14 are IRQ flags. We don't yet know:
- Are bits [15:0] all IRQ_STATUS, with ACCESS_ADDR in [31:16]? Unlikely — ACCESS_ADDR is 32 bits.
- Or does the hardware fully overlap both uses at [31:0], relying on the IRQ bits being always zero when writing the address?
- Need a live advertising session and trap right after an RX event to observe the lower bits being set.

## BB (0x40024200)

### Raw dump

Most registers read 0 — chip was halted before BLE stack fully initialized the BB.
Non-zero at some even/odd offsets are likely live timer/counter registers (BB runs its own clock domain).

```
+0x00  0x00000000  MAIN_CTRL  (BB_EN=0, not started)
+0x04  0x00000000  MODE_CTRL  (Idle)
+0x40  0x00000011  TX_PRE_DELAY = 17  (expected ~90 after init)
```

### Open question: are BB registers meaningful when BB_EN=0?

The BB block may have a separate power/clock enable. If CORE_EN and BB_EN are both 0, register writes may not latch. We cannot validate BB field layout until we capture a dump during active TX/RX.

## RFEND (0x40024300)

```
+0x08  0x00000000  RF_ANA_CTRL
+0x0C  0x00000000  CTRL
+0x28  0x00000480  CFG0 = 0x480 (default)
+0x44  0x00000000  PLL
```

CFG0 = 0x480 is the only non-trivial default. PLL = 0 means no channel is currently programmed.

### Open question: PLL formula verification

From assembly (rfend.o), the channel-to-PLL-word formula appears to be:
```
freq_offset = channel_mhz - 2400
int_div     = freq_offset / 64        (5-bit integer part, bits [24:20])
frac_div    = (freq_offset % 64) * 1024 / 250  (14-bit fractional, bits [13:0])
```
Not yet verified against a live channel program. Need to catch RFEND.PLL write during channel switch.

## AES (0x40025000)

```
+0x00  0x00000000  CTRL    (not running)
+0x04  0x00000000  STATUS  (BUSY=0)
+0x18..+0x24  0x00000000  DATA0-3  (no active operation)
```

DATA and KEY registers at +0x18–+0x34 are shared input/output. Writing KEY is write-only (confirmed by assembly — no read-back). LL_CTRL.LL_ENC_EN at +0x50 bit 7 enables hardware-assisted link-layer encryption.

### Open question: AES chaining mode

The CTRL register only has START (bit 0) and RESET (bit 8). No mode bits are visible. Is this always ECB? Or does the LL_CTRL path use a different chaining mode configured elsewhere?

## Summary table

| Register       | Offset | Initial belief    | Hardware value  | Assembly confirms | Status |
|----------------|--------|-------------------|-----------------|-------------------|--------|
| LLE CRC_INIT   | +0x04  | STATUS            | 0x00555555      | ✓ write in ll_advertise_tx | confirmed |
| LLE ACCESS_ADDR| +0x08  | IRQ_STATUS        | 0x8E89BED6      | ✓ write in ll_advertise_tx | confirmed |
| LLE IRQ_MASK   | +0x0C  | IRQ_MASK          | 0x00000000      | ✓ read in LLE_IRQSubHandler | confirmed |
| LLE STATE_MACHINE | +0x1C | STATE_MACHINE  | 108 = SLEEP     | (state enum from ASM) | confirmed |
| LLE +0x08 dual | +0x08  | single-purpose    | —               | ✓ W1C reads in IRQ handlers | confirmed dual-use |
| BB MAIN_CTRL   | +0x00  | as documented     | 0x00000000      | not init'd        | unverified |
| RFEND PLL      | +0x44  | formula derived   | 0x00000000      | not init'd        | unverified |
| AES chaining   | CTRL   | unknown           | —               | no mode bits seen | open question |

## files



/
//
aes_soft.o/
memory.o/
message.o/
tmos.o/
tmos_hw.o/
tmos_snv.o/
/0
att.o/
att_client.o/
att_server.o/
gap.o/
gap_central.o/
/22
gapgattserver.o/
gatt.o/
gatt_uuid.o/
gattclientapp.o/
gattservapp.o/
l2cap.o/
l2cap_input.o/
l2cap_output.o/
l2cap_sdu.o/
linkdb.o/
sm.o/
sm_initiator.o/
sm_pdu.o/
sm_responding.o/
sm_toolbox.o/
host_input.o/
host_output.o/
hci.o/
hci_control.o/
hci_host.o/
hci_slip.o/
hci_tl.o/
hci_tl_uart.o/
hci_uartLink.o/
ll.o/
ll_address.o/
ll_advertise.o/
ll_connect.o/
ll_core.o/
ll_hop.o/
ll_initiate.o/
ll_master.o/
ll_pdu.o/
ll_periodic .o/
ll_report.o/
/40
ll_scan.o/
ll_slave.o/
ll_sync.o/
ll_whitelist.o/
/60
aes.o/
bb.o/
ip.o/
lle.o/
rf_fh.o/
rfend.o/
api_c.o/
ctl_input.o/
ctl_output.o/
broadcaster.o/
central.o/
gapbondmgr.o/
observer.o/
peripheral.o/
role.o/
