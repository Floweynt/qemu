#ifndef HW_I386_X86_LIMINE_H
#define HW_I386_X86_LIMINE_H

#include "hw/i386/x86.h"
#include "hw/nvram/fw_cfg.h"

bool x86_load_limine(const char *kernel_filename,
                     FILE *f,
                     int kernel_file_size,
                     uint8_t *header,
                     FWCfgState *fw_cfg,
                     X86MachineState *x86ms);

#endif
