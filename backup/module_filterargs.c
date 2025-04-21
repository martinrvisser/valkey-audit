#include "valkeymodule.h"
#include <stdio.h>
#include <string.h>

static ValkeyModuleCommandFilter *filter;

// Command Filter callback function
void command_logger_callback(ValkeyModuleCommandFilterCtx *filter) {
    
    // Print each individual argument using snprintf and stdout
    char arg_buffer[1024];
    unsigned long long id = ValkeyModule_CommandFilterGetClientId(filter);
    fprintf(stderr, "client: %llu\n", id);
 
    int pos = 0;
    while (pos < ValkeyModule_CommandFilterArgsCount(filter)) {
        const ValkeyModuleString *arg = ValkeyModule_CommandFilterArgGet(filter, pos);
        size_t arg_len;
        const char *arg_str = ValkeyModule_StringPtrLen(arg, &arg_len);

        // Use snprintf to format the argument into a buffer
         snprintf(arg_buffer, sizeof(arg_buffer), "  Arg[%d]: '%.*s'", pos, (int)arg_len, arg_str);
        // Print to stdout
        printf("%s\n", arg_buffer);

        pos++;
    }
    
}

// Module initialization function
int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    VALKEYMODULE_NOT_USED(argv);
    VALKEYMODULE_NOT_USED(argc);

    // Initialize the module
    if (ValkeyModule_Init(ctx, "command_logger", 1, VALKEYMODULE_APIVER_1) 
        == VALKEYMODULE_ERR) 
        return VALKEYMODULE_ERR;

    if ((filter = ValkeyModule_RegisterCommandFilter(ctx, CommandFilter_CommandFilter, VALKEYMODULE_CMDFILTER_NOSELF ))
        == NULL) 
        return VALKEYMODULE_ERR;   
    
    return VALKEYMODULE_OK;
}

/* Clean up when module is unloaded */
int ValkeyModule_OnUnload(ValkeyModuleCtx *ctx) {
    VALKEYMODULE_NOT_USED(ctx);
    
    return VALKEYMODULE_OK;
}
