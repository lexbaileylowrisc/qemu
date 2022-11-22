# TomCrypt dependency

libtomcrypt_dep = subproject('libtomcrypt').get_variable('libtomcrypt_dep')

# OpenTitan devices

system_ss.add(when: 'CONFIG_OT_ALERT', if_true: files('ot_alert.c'))
system_ss.add(when: 'CONFIG_OT_AST', if_true: files('ot_ast.c'))
system_ss.add(when: 'CONFIG_OT_OTP', if_true: files('ot_otp.c'))
system_ss.add(when: 'CONFIG_OT_UART', if_true: files('ot_uart.c'))
