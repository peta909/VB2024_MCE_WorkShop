rule guloader_shellcode_config
{
    strings:
        $guloader_config_C2_updated_4 = {8B ?? 24 04}
     condition:
     any of them
}