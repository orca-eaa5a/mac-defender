#if defined(__WINDOWS__)
#pragma once
#endif
#ifndef __RSIGNAL_H
#define __RESIGNAL_H

#define RSIG_BASE                             0x4000
#define RSIG_UNKNOWN1                         0x4003
#define RSIG_GETEINFO                         0x4004 // Internally Used
#define RSIG_VIRINFO                          0x4005
#define RSIG_UNLOADENGINE                     0x400A
#define RSIG_SETUPENGINE                      0x400B // Internally Used
#define RSIG_SCANFILE_TS_W                    0x4014
#define RSIG_SCANPATH_TS_W                    0x4015
#define RSIG_INITENGINE						  0x4019 // Internally Used
#define RSIG_SETCLIENT_CONFIG                  0x401A // Internally Used
#define RSIG_RESERVED4                        0x401C
#define RSIG_FIW32_CONFIG                     0x401D
#define RSIG_SPLIT_VIRNAME                    0x401E
#define RSIG_HOOK_API                         0x401F
#define RSIG_INIT_ENGINE_CONTEXT              0x4020
#define RSIG_CLEANUP_ENGINE_CONTEXT           0x4021
#define RSIG_SCANFILE_TS_WCONTEXT             0x4023
#define RSIG_SCANPATH_TS_WCONTEXT             0x4024
#define RSIG_VIRINFO_FILTERED                 0x4025
#define RSIG_SCAN_OPEN                        0x4026
#define RSIG_SCAN_GETEVENT                    0x4027
#define RSIG_SCAN_CLOSE                       0x4028
#define RSIG_GET_THREAT_INFO                  0x4030
#define RSIG_SCANSTREAMW                      0x4031
#define RSIG_SCANSTREAMW_WCONTEXT             0x4032
#define RSIG_CHECK_PRIVILEGES                 0x4033
#define RSIG_ADJUST_PRIVILEGES                0x4034
#define RSIG_SET_FILECHANGEQUERY              0x4035
#define RSIG_BOOTENGINE                       0x4036 // Could externally Using
#define RSIG_RTP_GETINITDATA                  0x4037
#define RSIG_RTP_SETEVENTCALLBACK             0x4038
#define RSIG_RTP_NOTIFYCHANGE                 0x4039
#define RSIG_RTP_GETBEHAVIORCONTEXT           0x403A
#define RSIG_RTP_SETBEHAVIORCONTEXT           0x403B
#define RSIG_RTP_FREEBEHAVIORCONTEXT          0x403C
#define RSIG_SCAN_STREAMBUFFER                0x403D
#define RSIG_RTP_STARTBEHAVIORMONITOR         0x403E
#define RSIG_RTP_STOPBEHAVIORMONITOR          0x403F
#define RSIG_GET_SIG_DATA                     0x4041
#define RSIG_VALIDATE_FEATURE                 0x4042
#define RSIG_SET_CALLBACK                     0x4043
#define RSIG_OBFUSCATE_DATA                   0x4044
#define RSIG_DROP_BMDATA                      0x4045
#define RSIG_SCANEXTRACT                      0x4046
#define RSIG_CHANGE_SETTINGS                  0x4047
#define RSIG_RTSIG_DATA                       0x4048
#define RSIG_SYSTEM_REBOOT                    0x4049
#define RSIG_REVOKE_QUERY                     0x4050
#define RSIG_CHECK_EXCLUSIONS                 0x4051
#define RSIG_COMPLETE_INITIALIZATION          0x4052
#define RSIG_STATE_CHANGE                     0x4053
#define RSIG_SEND_CALLISTO_TELEMETRY          0x4054
#define RSIG_DYNAMIC_CONFIG                   0x4055
#define RSIG_SEND_EARLY_BOOT_DATA             0x4056
#define RSIG_SCAN_TCG_LOG                     0x4057
#define RSIG_CANCEL_ENGINE_LOAD               0x4058
#define RSIG_SQM_CONFIG                       0x4059
#define RSIG_SERVICE_NOTIFICATION             0x405A
#define RSIG_SCAN_TCG_LOG_EX                  0x405B
#define RSIG_FREE_TCG_EXTENDED_DATA           0x405C
#define RSIG_NOTIFY_MAINTENANCE_WINDOW_STATE  0x405D
#define RSIG_SEND_REMOTE_ATTESTATION_DATA     0x405E
#define RSIG_SUSPICIOUS_SCAN                  0x405F
#define RSIG_ON_CLOUD_COMPLETION              0x4060
#define RSIG_CONTROL_SPLI                     0x4061
#define RSIG_THREAT_UPDATE_STATUS             0x4062
#define RSIG_VERIFY_MACHINE_GUID              0x4063
#define RSIG_NRI_UPDATE_STATE                 0x4064
#define RSIG_TPM_CONFIG                       0x4065
#define RSIG_GET_RESOURCE_INFO                0x4066
#define RSIG_GET_ASYNC_QUEUE_LENGTH           0x4067
#define RSIG_RTP_IMAGENAME_CONFIG             0x4068
#define RSIG_SET_CUSTOM_SET_ID                0x4069
#define RSIG_CONFIGURE_ROLES                  0x4070
#define RSIG_HOOK_WOW                         0x4071
#define RSIG_AMSI_SESSION_END                 0x4072
#define RSIG_RESOURCE_CONTEXT_CONSOLIDATION   0x4073

#endif
