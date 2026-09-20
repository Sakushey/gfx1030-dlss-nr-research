// Generated from phase14d9_descriptor_audit.csv (33 rows, 33/33 descriptor_match_original=YES)
// by phase16 telemetry build prep. Matching: registration name CONTAINS the stem.
#pragma once
namespace bridge_registry {
struct KernelPolicy { const char* stem; const char* policy; unsigned dispatch_ptr; };
constexpr KernelPolicy kKernelPolicies[] = {
    { "10k_conv_res10ConvParams", "A2", 0 },
    { "10k_flag_setPjj", "A2", 0 },
    { "10k_qkv_attn10AttnParams", "B1", 1 },
    { "10k_swin_varILi128ELb0EEv9VarParams", "D", 0 },
    { "10k_swin_varILi256ELb0EEv9VarParams", "D", 0 },
    { "10k_swin_varILi32ELb0EEv9VarParams", "D", 0 },
    { "10k_swin_varILi32ELb1EEv9VarParams", "D", 0 },
    { "10k_swin_varILi64ELb0EEv9VarParams", "D", 0 },
    { "11k_attention12AttnParams1d", "A1", 0 },
    { "11k_contract212ConvParams1d", "A1", 0 },
    { "11k_conv_res211Conv2Params", "A1", 0 },
    { "11k_flag_waitPjjj", "A2", 0 },
    { "11k_qkv_attn210AttnParams", "C", 0 },
    { "11k_reproject12ReprojParams", "A1", 0 },
    { "12k_attention212AttnParams1d", "A1", 0 },
    { "12k_final_head10HeadParams", "A2", 0 },
    { "13k_conv_splitk12ConvParams1d", "A1", 0 },
    { "14k_dec_upsample11DecUpParams", "A2", 0 },
    { "14k_ffwd_inpview12FfwdPlParams", "A2", 0 },
    { "16k_conv_res_views12ConvPlParams", "A2", 0 },
    { "16k_swin_1h_32_fp810SwinParams", "B2", 1 },
    { "21k_pre_block_1h_32_fp89PreParams", "B2", 1 },
    { "22k_post_block_1h_32_fp810PostParams", "B2", 1 },
    { "5k_qkv9QkvParams", "A1", 0 },
    { "6k_ffwd10FfwdParams", "A2", 0 },
    { "6k_mean10MeanParams", "A2", 0 },
    { "6k_qkv29QkvParams", "A1", 0 },
    { "7k_ffwd211Ffwd2Params", "A1", 0 },
    { "8k_expand12ExpandParams", "A1", 0 },
    { "8k_export12ExportParams", "A1", 0 },
    { "8k_import12ImportParams", "A1", 0 },
    { "8k_repack12RepackParams", "A2", 0 },
    { "9k_expand212ExpandParams", "A1", 0 },
};
constexpr unsigned kKernelPolicyCount = 33;
}  // namespace bridge_registry

