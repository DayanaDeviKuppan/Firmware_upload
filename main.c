#include <stdint.h>
#include <stddef.h>
#include "secure_island.h"
#include "dma.h"
#include "errors.h"
#include "sha256.h"
#include "io.h"

#define CRYPTO_IO_BUFFER_SIZE   4096U
#define DMA_TRANSFER_TIMEOUT    1000000U
#define MAILBOX                 ((volatile Mailbox_Type *)(MAILBOX_BASE))
#define SECURE_ENCLAVE_HART_ID   1U

static uint8_t global_input_buf[CRYPTO_IO_BUFFER_SIZE];
static uint8_t global_output_buf[32];

static volatile int request_pending = 0;

static inline void fence(void) {
    __asm__ volatile ("fence rw, rw" ::: "memory");
}

typedef enum {
    DMA_ERR_CONFIG       = 0xC1U,
    DMA_ERR_ENABLE       = 0xC2U,
    DMA_ERR_STATUS_READ  = 0xC3U,
    DMA_ERR_TIMEOUT      = 0xC4U,
    DMA_ERR_DISABLE      = 0xC5U,
    DMA_ERR_CLEAR_FLAGS  = 0xC6U,
} dma_err_t;

static uint16_t Dma_Fetch_Store(uint32_t src_addr, uint32_t dest_addr,
                                 uint32_t src_len_bytes) {

    DMA_Config_t dma_config = {0};
    uint16_t ret = 0U;
    uint8_t status = 0U;
    uint64_t timeout = 0ULL;
    uint8_t transfer_done = 0U;

    dma_config.chn_no           = DMA_CHANNEL_0;
    dma_config.src_addr         = (uint32_t *)src_addr;
    dma_config.dest_addr        = (uint32_t *)dest_addr;
    dma_config.src_data_size    = DMA_BYTE;
    dma_config.dest_data_size   = DMA_BYTE;
    dma_config.transfer_length  = src_len_bytes;
    dma_config.priority         = DMA_PRIORITY_HIGH;
    dma_config.dest_qspi_type   = DMA_QSPI_UNKNOWN;

    ret = DMA_Transfer_Configure(&dma_config);
    if (ret != SUCCESS) {
        return DMA_ERR_CONFIG;
    }

    ret = DMA_Channel_Set_State(&dma_config, true);
    if (ret != SUCCESS) {
        return DMA_ERR_ENABLE;
    }

    for (timeout = DMA_TRANSFER_TIMEOUT; timeout > 0U; timeout--) {
        ret = DMA_Interrupt_Status(&dma_config, &status);
        if (ret != SUCCESS) {
            return DMA_ERR_STATUS_READ;
        }
        if ((status & 0x07U) == 0x07U) {
            transfer_done = 1U;
            break;
        }
    }

    if (transfer_done == 0U) {
        return DMA_ERR_TIMEOUT;
    }

    ret = DMA_Channel_Set_State(&dma_config, false);
    if (ret != SUCCESS) {
        return DMA_ERR_DISABLE;
    }

    ret = DMA_Clear_Interrupt_Flags(&dma_config, 1U, 1U, 1U, 1U);
    if (ret != SUCCESS) {
        return DMA_ERR_CLEAR_FLAGS;
    }

    return SUCCESS;
}

extern volatile uint64_t *msip;
void on_machine_software_interrupt(void) {
    volatile uint32_t* msip = (volatile uint32_t*)
                              (CLINT0_BASE + SECURE_ENCLAVE_HART_ID * 4U);
    *msip = 0U;
    request_pending = 1;
}

static void Process_Mailbox_Request(void) {
    fence();

    if (MAILBOX->magic != MAILBOX_MAGIC) {
        return; /* stale mailbox state */
    }

    if (MAILBOX->opcode != CRYPTO_ALGO_SHA256) {
        MAILBOX->crypto_status = CRYPTO_STATUS_NOT_RUN;
        fence();
        MAILBOX->comm_status = MB_TRANSPORT_ERROR;
        fence();
        return;
    }

    uint32_t input_len_bytes = (MAILBOX->input_len_bits + 7U) / 8U;
    if (input_len_bytes > CRYPTO_IO_BUFFER_SIZE) {
        MAILBOX->crypto_status = CRYPTO_STATUS_NOT_RUN;
        fence();
        MAILBOX->comm_status = MB_TRANSPORT_ERROR;
        fence();
        return;
    }

    MAILBOX->comm_status = MB_IN_PROGRESS;
    fence();

    if (Dma_Fetch_Store(MAILBOX->input_addr, (uint32_t)(uintptr_t)global_input_buf,
                         input_len_bytes) != 0) {
        MAILBOX->crypto_status = CRYPTO_STATUS_NOT_RUN;
        fence();
        MAILBOX->comm_status = MB_TRANSPORT_ERROR;
        fence();
        return;   /* crypto_lib is never called on a failed fetch */
    }

    uint16_t crypto_result = SHA256_Single_Run(global_output_buf, global_input_buf,
                                                MAILBOX->input_len_bits);
    if (Dma_Fetch_Store((uint32_t)(uintptr_t)global_output_buf, MAILBOX->output_addr,
                         sizeof(global_output_buf)) != 0) {
        MAILBOX->crypto_status = CRYPTO_STATUS_NOT_RUN;
        fence();
        MAILBOX->comm_status = MB_TRANSPORT_ERROR;
        fence();
        return;
    }

    MAILBOX->crypto_status = crypto_result;
    fence();
    MAILBOX->comm_status = MB_RESPONSE_READY;
    fence();
}

static void Enable_Machine_Software_Interrupt(void) {
    __asm__ volatile ("csrs mie, %0"     :: "r"(1UL << 3));
    __asm__ volatile ("csrs mstatus, %0" :: "r"(1UL << 3));
}

static void Mailbox_Init(void) {
    MAILBOX->comm_status = MB_IDLE;
    fence();
}

int main(void) {
    Mailbox_Init();
    Enable_Machine_Software_Interrupt();

    while (1) {
        __asm__ volatile ("wfi");
        if (request_pending) {
            request_pending = 0;
            Process_Mailbox_Request();
        }
    }
    return SUCCESS;
}