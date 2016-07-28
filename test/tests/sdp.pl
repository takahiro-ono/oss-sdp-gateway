@sdp = (
    {
        'category' => 'controller',
        'subcategory' => 'server+ctrl',
        'detail'   => 'server gets access data from ctrl',
        'function' => \&controller_cycle,
        # 'cmdline'  => $default_client_args_sdp,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args_sdp $intf_str",
        # 'server_sending_spa' => 1,
        # 'fw_rule_created' => $NEW_RULE_REQUIRED,
        # 'fw_rule_removed' => $NEW_RULE_REMOVED,
        'server_positive_output_matches' => 
            [qr/All new credentials stored successfully/,
             qr/Succeeded in retrieving and installing access configuration/],
        'ctrl_positive_output_matches' => 
            [qr/New credentials successfully created/,
             qr/Successfully stored new keys/,
             qr/Received access data acknowledgement/,
             qr/Found and removed SDP ID/],
    },
    {
        'category' => 'controller',
        'subcategory' => 'all 3 components',
        'detail'   => 'add client to mix',
        'function' => \&controller_cycle,
        'cmdline'  => $default_client_args_sdp,
        'fwknopd_cmdline'  => "$fwknopdCmd $default_server_conf_args_sdp $intf_str",
        # 'server_sending_spa' => 1,
        'fw_rule_created' => $NEW_RULE_REQUIRED,
        'client_positive_output_matches' =>
            [qr/All new credentials stored successfully/],
        'server_positive_output_matches' => 
            [qr/Succeeded in retrieving and installing access configuration/,
             qr/Succeeded in modifying access data/],
        'ctrl_positive_output_matches' => 
            [qr/New credentials successfully created/,
             qr/Successfully stored new keys/,
             qr/Received access data acknowledgement/,
             qr/Found and removed SDP ID/],
    },
);