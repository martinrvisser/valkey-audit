#include "valkeymodule.h"

#include <string.h>
#include <strings.h>

static ValkeyModuleString *log_key_name;

static const char log_command_name[] = "commandfilter.log";
static const char retained_command_name[] = "commandfilter.retained";
static int in_log_command = 0;

static ValkeyModuleCommandFilter *filter, *filter1;
static ValkeyModuleString *retained;

int CommandFilter_Retained(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc)
{
    (void) argc;
    (void) argv;

    if (retained) {
        ValkeyModule_ReplyWithString(ctx, retained);
    } else {
        ValkeyModule_ReplyWithNull(ctx);
    }

    return VALKEYMODULE_OK;
}

int CommandFilter_LogCommand(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc)
{
    ValkeyModuleString *s = ValkeyModule_CreateString(ctx, "", 0);

    int i;
    for (i = 1; i < argc; i++) {
        size_t arglen;
        const char *arg = ValkeyModule_StringPtrLen(argv[i], &arglen);

        if (i > 1) ValkeyModule_StringAppendBuffer(ctx, s, " ", 1);
        ValkeyModule_StringAppendBuffer(ctx, s, arg, arglen);
    }

    ValkeyModuleKey *log = ValkeyModule_OpenKey(ctx, log_key_name, VALKEYMODULE_WRITE|VALKEYMODULE_READ);
    ValkeyModule_ListPush(log, VALKEYMODULE_LIST_HEAD, s);
    ValkeyModule_CloseKey(log);
    ValkeyModule_FreeString(ctx, s);

    in_log_command = 1;

    size_t cmdlen;
    const char *cmdname = ValkeyModule_StringPtrLen(argv[1], &cmdlen);
    ValkeyModuleCallReply *reply = ValkeyModule_Call(ctx, cmdname, "v", &argv[2], argc - 2);
    if (reply) {
        ValkeyModule_ReplyWithCallReply(ctx, reply);
        ValkeyModule_FreeCallReply(reply);
    } else {
        ValkeyModule_ReplyWithSimpleString(ctx, "Unknown command or invalid arguments");
    }

    in_log_command = 0;

    return VALKEYMODULE_OK;
}

void CommandFilter_CommandFilter(ValkeyModuleCommandFilterCtx *filter)
{
    unsigned long long id = ValkeyModule_CommandFilterGetClientId(filter);

    if (in_log_command) return;  /* don't process our own RM_Call() from CommandFilter_LogCommand() */

   // Get client info
   unsigned long long client = ValkeyModule_CommandFilterGetClientId(filter);

   // Buffer for the audit message
   char buffer[1024];
   char cmd[256] = ""; // what about LUA and the length?

   int log = 1;
   int pos = 0;
   const ValkeyModuleString *arg = ValkeyModule_CommandFilterArgGet(filter, pos);
   size_t arg_len;
   const char *arg_str = ValkeyModule_StringPtrLen(arg, &arg_len);
   strcat(cmd, arg_str);
   //while (pos < ValkeyModule_CommandFilterArgsCount(filter)) {
   //    const ValkeyModuleString *arg = ValkeyModule_CommandFilterArgGet(filter, pos);
   //    size_t arg_len;
   //    const char *arg_str = ValkeyModule_StringPtrLen(arg, &arg_len);
   //    strcat(cmd, arg_str);
   //    pos++;
   //}

   if (client) {
       snprintf(buffer, sizeof(buffer), "Client %llu executed command: %s", 
                client, cmd[0] ? cmd : "unknown");
   } else {
       snprintf(buffer, sizeof(buffer), "Client executed command: %s", 
                cmd[0] ? cmd : "unknown");
   }
        
   // Log the message
   //logAuditMessageDirect(buffer);
   if (log) 
   printf("cmd: %s\n", buffer);

   //ValkeyModule_CommandFilterArgInsert(filter, 0,
   //         ValkeyModule_CreateString(NULL, log_command_name, sizeof(log_command_name)-1));
}

int ValkeyModule_OnLoad(ValkeyModuleCtx *ctx, ValkeyModuleString **argv, int argc) {
    if (ValkeyModule_Init(ctx,"commandaudit",1,VALKEYMODULE_APIVER_1)
            == VALKEYMODULE_ERR) return VALKEYMODULE_ERR;

    if (argc != 2 && argc != 3) {
        ValkeyModule_Log(ctx, "warning", "Log key name not specified");
        return VALKEYMODULE_ERR;
    }

    long long noself = 0;
    log_key_name = ValkeyModule_CreateStringFromString(ctx, argv[0]);
    ValkeyModule_StringToLongLong(argv[1], &noself);

    if ((filter = ValkeyModule_RegisterCommandFilter(ctx, CommandFilter_CommandFilter, 
                    noself ? VALKEYMODULE_CMDFILTER_NOSELF : 0))
            == NULL) return VALKEYMODULE_ERR;

    if (argc == 3) {
        const char *ptr = ValkeyModule_StringPtrLen(argv[2], NULL);
        if (!strcasecmp(ptr, "noload")) {
            /* This is a hint that we return ERR at the last moment of OnLoad. */
            ValkeyModule_FreeString(ctx, log_key_name);
            if (retained) ValkeyModule_FreeString(NULL, retained);
            return VALKEYMODULE_ERR;
        }
    }

    return VALKEYMODULE_OK;
}

int ValkeyModule_OnUnload(ValkeyModuleCtx *ctx) {
    ValkeyModule_FreeString(ctx, log_key_name);
    if (retained) ValkeyModule_FreeString(NULL, retained);

    return VALKEYMODULE_OK;
}