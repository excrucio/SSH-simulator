   M S B A M L   `   `   `  ���� H  DSSH-simulator, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null-clr-namespace:SSH_simulatorSSH_simulator      SSH_simulator.MainWindow   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     @d2http://schemas.microsoft.com/expression/blend/2008     Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     -localclr-namespace:SSH_simulator       � Title$  SSH simulator�� � WindowStartupLocation$ CenterScreen=�$	��940��$	��650�� � WindowState$ 	Maximized=�.��(�  (� Stretch$
 Fill=�.��� $
��1288�� � ColumnDefinitions �� $
��1594 �.+��� -    ��Name$ textBox_client��$
��Left=�$	��191��$��7,35,0,0q�$	��Top=�$	��489��" �� VerticalScrollBarVisibility$
 Auto=���.  �� 
IsReadOnly . $��Consolas)� �� AcceptsReturn . 	 �� 
AcceptsTab	 . 
 �� TextWrapping$

 Wrap=��� -   $ textBox_client_decoded��$
��Left=�$	��191��$��
503,36,0,0q�$

 Wrap=�$	��Top=�$	��483����. $
 Auto=� � UseLayoutRounding . $ �� HorizontalScrollBarVisibility$
 Auto=� . $��Consolas)� . 	 . �� -   $ textBox_server��$
��Left=�$	��200��$��	7,262,0,0q�$	��Top=�$	��489��$
 Auto=���.  . $��Consolas)� . 	 . $

 Wrap=��� -   $ textBox_server_decoded��$
��Left=�$	��200��$��503,262,0,0q�$

 Wrap=�$	��Top=�$	��483����. $
 Auto=� .  . $��Consolas)� . 	 . �� -    ��Name$ 
tabControl��$
��Left=�$	��323��$��	7,507,0,0q�$	��Top=�$
��1271��.@��� -    ��Name$ tab_algoritmi��$��	Algoritmi��.��� ���	#FFE5E5E5 �� .+��� -    ��Name$ gridSplitter��$
��Left=�$	��321��$��643,-1,0,-25q�$	��Top=�$��5���� -   $ textBox_clientIdent��$
��Left=�$��23��$��	282,3,0,0q�$

 Wrap=�$��SSH-2.0-klijent_v1.0��$	��Top=�$	��248���� -	   $ textBox_serverIdent��$
��Left=�$��23��$��	936,2,0,0q�$

 Wrap=�$��SSH-2.0-server_v1.0��$	��Top=�$	��248���� -
    ��Name$ label7��$��Identifikacijski niz��$
��Left=�$��	174,0,0,0q�$	��Top=��� -   $ label6��$��Identifikacijski niz��$
��Left=�$��
828,-1,0,0q�$	��Top=��� -   $ label8��$��Diffie-Hellman��$
��Left=�$��	10,32,0,0q�$	��Top=�$
��Bold"��� -   $ label9��$��Digitalni potpis��$
��Left=�$��
205,32,0,0q�$	��Top=�$
��Bold"��� -   $ label10��$��
Enkripcija��$
��Left=�$��
384,32,0,0q�$	��Top=�$
��Bold"��� -   $ label11��$	��MAC��$
��Left=�$��
519,32,0,0q�$	��Top=�$
��Bold"��� -   $ label46��$!��diffie-hellman-group14-sha1��$
��Left=�$��
10,107,0,0q�$	��Top=��� -   $ label45��$ ��diffie-hellman-group1-sha1��$
��Left=�$��	10,81,0,0q�$	��Top=��� -    ��Name$! checkBox_ecdh_sha2_nistp521��$��ecdh-sha2-nistp521��$
��Left=�$��	18,61,0,0q�$	��Top=� �� 	ClickMode$ Press=��� -   $ checkBox_ssh_rsa��$��ssh-rsa��$
��Left=�$��
206,81,0,0q�$	��Top=� d� 	IsChecked$
 TrueY�{�.  �� -   $ label47��$��ssh-dss��$
��Left=�$��214,101,0,0q�$	��Top=��� -   $ label48��$��3des-cbc��$
��Left=�$��
391,81,0,0q�$	��Top=��� -   $ checkBox_aes256_cbc��$��
aes256-cbc��$
��Left=�$��
384,63,0,0q�$	��Top=�{�.  �� -   $ checkBox_blowfish_ctr��$��blowfish-ctr��$
��Left=�$��384,112,0,0q�$	��Top=� J� RenderTransformOrigin$ 0.5,0.5&�z�V� .~��� �� �� T�  T� X$ 0.889Q��� -   $ checkBox_gost28147��$��	gost28147��$
��Left=�$��519,113,0,0q�$	��Top=��� -   $ checkBox_hmac_sha2��$��	hmac-sha2��$
��Left=�$��
519,92,0,0q�$	��Top=��� -   $ label49��$��	hmac-sha1��$
��Left=�$��
529,64,0,0q�$	��Top=��� -   $ label8_Copy��$��Diffie-Hellman��$
��Left=�$��
661,32,0,0q�$	��Top=�$
��Bold"��� -   $ label9_Copy��$��Digitalni potpis��$
��Left=�$��
866,32,0,0q�$	��Top=�$
��Bold"��� -   $ label10_Copy��$��
Enkripcija��$
��Left=�$��1035,32,0,0q�$	��Top=�$
��Bold"��� -   $ label11_Copy��$	��MAC��$
��Left=�$��1170,32,0,0q�$	��Top=�$
��Bold"��� -   $ label46_Copy��$!��diffie-hellman-group14-sha1��$
��Left=�$��661,107,0,0q�$	��Top=��� -    $ label45_Copy��$ ��diffie-hellman-group1-sha1��$
��Left=�$��
661,81,0,0q�$	��Top=��� -!   $( "checkBox_server_ecdh_sha2_nistp521��$��ecdh-sha2-nistp521��$
��Left=�$��
670,63,0,0q�$	��Top=�$ Press=��� -"   $ checkBox_server_ssh_rsa��$��ssh-rsa��$
��Left=�$��
866,84,0,0q�$	��Top=�$
 TrueY�{�.  �� -#   $ label47_Copy��$��ssh-dss��$
��Left=�$��866,102,0,0q�$	��Top=��� -$   $ label48_Copy��$��3des-cbc��$
��Left=�$��1057,81,0,0q�$	��Top=��� -%   $  checkBox_server_aes256_cbc��$��
aes256-cbc��$
��Left=�$��1035,63,0,0q�$	��Top=�{�.  �� -&   $" checkBox_server_blowfish_ctr��$��blowfish-ctr��$
��Left=�$��1035,112,0,0q�$	��Top=��� -'   $ checkBox_server_gost28147��$��	gost28147��$
��Left=�$��1168,112,0,0q�$	��Top=��� -(   $ checkBox_server_hmac_sha2��$��	hmac-sha2��$
��Left=�$��1166,92,0,0q�$	��Top=��� -)   $ label49_Copy��$��	hmac-sha1��$
��Left=�$��1170,64,0,0q�$	��Top=��� -*   $" checkBox_ecdsa_sha2_nistp384��$��ecdsa-ssh2-nistp384��$
��Left=�$��
206,58,0,0q�$	��Top=��� -+   $) #checkBox_server_ecdsa_sha2_nistp384��$��ecdsa-ssh2-nistp384��$
��Left=�$��
866,61,0,0q�$	��Top=��� -,   $ tab_dh��$��Diffie-Hellman��.��� ���	#FFE5E5E5 �� .+��� --   $ label_krivulja��$��Modul, p��$
��Left=�$��	10,10,0,0q�$	��Top=��� -.   $ label_G��$��Generator, g��$
��Left=�$��	10,36,0,0q�$	��Top=��� -/   $ label_privatni_kljuc_DH��$��Eksponent, x��$
��Left=�$��	10,62,0,0q�$	��Top=��� -0   $ label_javni_kljuc��$��e = g^x mod p��$
��Left=�$��	10,88,0,0q�$	��Top=��� -1   $ label_privatni_kljuc��$ ��Tajni ključ K = f^x mod p��$
��Left=�$��
10,114,0,0q�$	��Top=��� -2   $ label17��$��Hash razmjene, H��$
��Left=�$��
10,140,0,0q�$	��Top=��� -3   $ label18��$��Javni ključ servera��$
��Left=�$��
10,165,0,0q�$	��Top=��� -4   $ label19��$��Digitalni potpis servera��$
��Left=�$��
10,191,0,0q�$	��Top=��� -5   $ gridSplitter_Copy��$
��Left=�$	��281��$��	625,0,0,0q�$	��Top=�$��6���� -6   $ label_ser_krivulja��$��Modul, p��$
��Left=�$��
636,10,0,0q�$	��Top=��� -7   $ label_ser_G��$��Generator, g��$
��Left=�$��
636,36,0,0q�$	��Top=��� -8   $! label_ser_privatni_kljuc_DH��$��Eksponent, y��$
��Left=�$��
636,62,0,0q�$	��Top=��� -9   $ label_ser_javni_kljuc��$��f = g^y mod p��$
��Left=�$��
636,88,0,0q�$	��Top=��� -:   $ label_ser_privatni_kljuc��$ ��Tajni ključ K = e^y mod p��$
��Left=�$��636,114,0,0q�$	��Top=��� -;   $ label26��$��Digitalni potpis od H��$
��Left=�$��636,165,0,0q�$	��Top=��� -<   $ label25��$��Hash razmjene, H��$
��Left=�$��636,140,0,0q�$	��Top=��� -=   $ label28��$��
DSA ključ��$
��Left=�$��636,217,0,0q�$	��Top=�$y�Hidden=��� ->   $ label27��$��
RSA ključ��$
��Left=�$��636,191,0,0q�$	��Top=�$y�Hidden=��� -?   $ textBox_RSA��$
��Left=�$��23��$��791,197,0,0q�$	��Top=�$	��356��$ Disabled=�{�.  $y�Hidden=��� -@   $ textBox_DSA��$
��Left=�$��23��$��791,220,0,0q�$	��Top=�$	��356��$ Disabled=�{�.  $y�Hidden=��� -A    ��Name$ 
button_RSA��$��odaberi��$
��Left=�$��1152,198,0,0q�$	��Top=�$��75��{�.  $y�Hidden=��� -B   $ 
button_DSA��$��odaberi��$
��Left=�$��1152,221,0,0q�$	��Top=�$��75��{�.  $y�Hidden=��� -C   $ textBox_ser_mod_p��$
��Left=�$��23��$��
791,10,0,0q�$	��Top=�$	��436��$ Disabled=� �� CharacterCasing$ Lower=��� -D   $ textBox_ser_g��$
��Left=�$��23��$��
791,36,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -E   $ 	textBox_y��$
��Left=�$��23��$��
791,62,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -F   $ 	textBox_f��$
��Left=�$��23��$��
791,88,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -G   $ textBox_ser_K��$
��Left=�$��23��$��791,114,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -H   $ textBox_ser_H��$
��Left=�$��23��$��791,140,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -I   $ textBox_sig_H��$
��Left=�$��23��$��791,165,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -J   $ textBox_cli_mod_p��$
��Left=�$��23��$��
173,10,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -K   $ textBox_cli_g��$
��Left=�$��23��$��
173,36,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -L   $ 	textBox_x��$
��Left=�$��23��$��
173,62,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -M   $ 	textBox_e��$
��Left=�$��23��$��
173,88,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -N   $ textBox_cli_K��$
��Left=�$��23��$��173,114,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -O   $ textBox_cli_H��$
��Left=�$��23��$��173,140,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -P   $ textBox_ser_pub_key��$
��Left=�$��23��$��173,165,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -Q   $ textBox_sig_ser��$
��Left=�$��23��$��173,193,0,0q�$	��Top=�$	��436��$ Disabled=�$ Lower=��� -R   $ tab_keys��$��Generiranje ključeva��$
��Left=�$��20��$	��Top=�$	��125��$��-2,-2,-66,0q�.��� ���	#FFE5E5E5 �� .+��� -S   $ gridSplitter_Copy1��$
��Left=�$	��281��$��	635,0,0,0q�$	��Top=�$��6���� -T   $ label30��$��
Sažetak H��$
��Left=�$��	11,72,0,0q�$	��Top=��� -U   $ label29��$��Tajni ključ K��$
��Left=�$��	10,41,0,0q�$	��Top=��� -V   $ label31��$��vektor klijent - server��$
��Left=�$��
10,103,0,0q�$	��Top=��� -W   $ label32��$��vektor server - klijent��$
��Left=�$��
10,134,0,0q�$	��Top=��� -X   $ label33��$(��"ključ enkripcije klijent - server��$
��Left=�$��
10,165,0,0q�$	��Top=��� -Y   $ label34��$(��"ključ enkripcije server - klijent��$
��Left=�$��
11,196,0,0q�$	��Top=��� -Z   $ label35��$!��MAC ključ klijent - server��$
��Left=�$��
11,227,0,0q�$	��Top=��� -[   $ label36��$!��MAC ključ server - klijent��$
��Left=�$��
11,258,0,0q�$	��Top=��� -\   $ label30_Copy��$��
Sažetak H��$
��Left=�$��
646,75,0,0q�$	��Top=��� -]   $ label29_Copy��$��Tajni ključ K��$
��Left=�$��
645,44,0,0q�$	��Top=��� -^   $ label31_Copy��$��vektor klijent - server��$
��Left=�$��645,106,0,0q�$	��Top=��� -_   $ label32_Copy��$��vektor server - klijent��$
��Left=�$��645,137,0,0q�$	��Top=��� -`   $ label33_Copy��$(��"ključ enkripcije klijent - server��$
��Left=�$��645,168,0,0q�$	��Top=��� -a   $ label34_Copy��$(��"ključ enkripcije server - klijent��$
��Left=�$��646,199,0,0q�$	��Top=��� -b   $ label35_Copy��$!��MAC ključ klijent - server��$
��Left=�$��646,230,0,0q�$	��Top=��� -c   $ label36_Copy��$!��MAC ključ server - klijent��$
��Left=�$��646,261,0,0q�$	��Top=��� -d   $ textBox_cli_cry_c_s��$
��Left=�$��23��$��181,168,0,0q�$	��Top=�$	��449��$ Disabled=��� -e   $ textBox_cli_s_c��$
��Left=�$��23��$��181,137,0,0q�$	��Top=�$	��449��$ Disabled=��� -f   $ textBox_cli_c_s��$
��Left=�$��23��$��181,106,0,0q�$	��Top=�$	��449��$ Disabled=��� -g   $ textBox_cli_H1��$
��Left=�$��23��$��
181,75,0,0q�$	��Top=�$	��449��$ Disabled=��� -h   $ textBox_cli_K1��$
��Left=�$��23��$��
181,44,0,0q�$	��Top=�$	��449��$ Disabled=��� -i   $ textBox_cli_cry_s_c��$
��Left=�$��23��$��181,199,0,0q�$	��Top=�$	��449��$ Disabled=��� -j   $ textBox_cli_MAC_c_s��$
��Left=�$��23��$��181,230,0,0q�$	��Top=�$	��449��$ Disabled=��� -k   $ textBox_cli_MAC_s_c��$
��Left=�$��23��$��181,261,0,0q�$	��Top=�$	��449��$ Disabled=��� -l   $ textBox_ser_cry_c_s��$
��Left=�$��23��$��814,171,0,0q�$	��Top=�$	��449��$ Disabled=��� -m   $ textBox_ser_s_c��$
��Left=�$��23��$��814,140,0,0q�$	��Top=�$	��449��$ Disabled=��� -n   $ textBox_ser_c_s��$
��Left=�$��23��$��814,109,0,0q�$	��Top=�$	��449��$ Disabled=��� -o   $ textBox_ser_H1��$
��Left=�$��23��$��
814,78,0,0q�$	��Top=�$	��449��$ Disabled=��� -p   $ textBox_ser_K1��$
��Left=�$��23��$��
814,47,0,0q�$	��Top=�$	��449��$ Disabled=��� -q   $ textBox_ser_cry_s_c��$
��Left=�$��23��$��814,202,0,0q�$	��Top=�$	��449��$ Disabled=��� -r   $ textBox_ser_MAC_c_s��$
��Left=�$��23��$��814,233,0,0q�$	��Top=�$	��449��$ Disabled=��� -s   $ textBox_ser_MAC_s_c��$
��Left=�$��23��$��814,264,0,0q�$	��Top=�$	��449��$ Disabled=��� -t   $ label51��$��ENKRIPCIJA:��$
��Left=�$��	57,15,0,0q�$	��Top=�$ 0.535,0.222&�$
��Bold"�$��11(��� -u   $ label52��$��MAC algoritam:��$
��Left=�$��
342,13,0,0q�$	��Top=�$
��Bold"�$��11(��� -v   $ label_cli_cry��$�� ��$
��Left=�$��
136,15,0,0q�$	��Top=�$ 0.318,0.352&�$
��Bold"�$��11(��� -w   $ label_cli_mac��$�� ��$
��Left=�$��
439,15,0,0q�$	��Top=�$
��Bold"�$��11(��� -x   $ label51_Copy��$��ENKRIPCIJA:��$
��Left=�$��
697,13,0,0q�$	��Top=�$ 0.535,0.222&�$
��Bold"�$��11(��� -y   $ label52_Copy��$��MAC algoritam:��$
��Left=�$��
982,11,0,0q�$	��Top=�$
��Bold"�$��11(��� -z   $ label_ser_cry��$�� ��$
��Left=�$��
776,13,0,0q�$	��Top=�$ 0.318,0.352&�$
��Bold"�$��11(��� -{   $ label_ser_mac��$�� ��$
��Left=�$��1079,13,0,0q�$	��Top=�$
��Bold"�$��11(��� -|   $ tab_auth��$��Autentifikacija��$
��Left=�$��20��$	��Top=�$��94��$��-2,-2,-35,0q�.��� ���	#FFE5E5E5 �� .+��� -}   $ gridSplitter_Copy2��$
��Left=�$	��281��$��	641,0,0,0q�$	��Top=�$��6���� -~   $ label37��$��login��$
��Left=�$��	20,22,0,0q�$	��Top=�$ 1.594,0.439&��� -   $ label38��$��lozinka��$
��Left=�$��	20,53,0,0q�$	��Top=��� -�   $ label39��$��Baza korisnika��$
��Left=�$��
683,25,0,0q�$	��Top=��� -�   $ textBox_baza_korisnika��$
��Left=�$��23��$��
773,26,0,0q�$	��Top=�$	��373��$��UsersDB.txt���� -�   $ button_baza_korisnika��$��odaberi��$
��Left=�$��1162,28,0,0q�$	��Top=�$��75���� -�   $ textBox_login��$
��Left=�$��23��$��	92,26,0,0q�$
��root��$	��Top=�$	��493���� -�   $ textBox_pass��$
��Left=�$��23��$��	92,57,0,0q�$
��toor��$	��Top=�$	��493���� -�   $ tab_protokol��$��Protokol��$
��Left=�$��20��$	��Top=�$��65��$��
-2,-2,-6,0q�.��� ���	#FFE5E5E5 �� .+��� -�   $ label41��$#��udaljeni identifikator kanala��$
��Left=�$��
212,10,0,0q�$	��Top=��� -�   $ label42��$��veličina prozora (Byte)��$
��Left=�$��	10,36,0,0q�$	��Top=��� -�   $ label40��$"��lokalni identifikator kanala��$
��Left=�$��	10,10,0,0q�$	��Top=��� -�   $ label41_Copy��$#��udaljeni identifikator kanala��$
��Left=�$��
854,40,0,0q�$	��Top=��� -�   $ label40_Copy��$"��lokalni identifikator kanala��$
��Left=�$��	854,9,0,0q�$	��Top=��� -�   $ textBox_naredba��$
��Left=�$��23��$��
373,41,0,0q�$

 Wrap=�$	��Top=�$	��205��$ Disabled=�$��
tree /F /A���� -�   $ label43��$��Naredba za izvršavanje*��$
��Left=�$��
212,36,0,0q�$	��Top=��� -�   $ textBox_rezultat��$
��Left=�$	��184��$��	10,97,0,0q�$	��Top=�$	��667��$
 Auto=�$ Visible=��� -�   $ label44��$��Rezultat naredbe��$
��Left=�$��	10,71,0,0q�$	��Top=��� -�   $# textBox_server_udaljeni_kanal��$
��Left=�$��23��$��1027,40,0,0q�$

 Wrap=�$	��Top=�$	��120��$ Disabled=� . �� -�   $$ textBox_klijent_udaljeni_kanal��$
��Left=�$��23��$��
373,13,0,0q�$

 Wrap=�$	��Top=�$��47��$ Disabled=� . �� -�   $# textBox_klijent_lokalni_kanal��$
��Left=�$��23��$��
159,13,0,0q�$

 Wrap=�$	��Top=�$��47��$ Disabled=� . �� -�   $ textBox_velicina_prozora��$
��Left=�$��23��$��
159,41,0,0q�$	��Top=�$��47��$ Disabled=�$	��240���� -�   $" textBox_server_lokalni_kanal��$
��Left=�$��23��$��
1027,9,0,0q�$

 Wrap=�$	��Top=�$	��120��$ Disabled=� . �� -�   $ gridSplitter_Copy3��$
��Left=�$	��288��$��711,12,0,-5q�$	��Top=�$��6��$ 0.5,0.5&�z�V� .~���  �� ScaleX$ -1Q��� �� T� �� -�   $ label53��$5��/*naredba se zaista izvrši na računalu/serveru��$
��Left=�$��
373,55,0,0q�$	��Top=�$��10(��� -�   $ button_next��$��Idući korak��$
��Left=�$��44��$��	991,7,0,0q�$	��Top=�$	��140���� -�   $ button_reset��$��Reset��$
��Left=�$��44��$��
1136,7,0,0q�$	��Top=�$	��140���� -�   $ label��$��Klijent��$
��Left=�$��	10,10,0,0q�$	��Top=�$
��Bold"��� -�   $ label1��$��Klijent dekodirano��$
��Left=�$��
496,10,0,0q�$	��Top=�$
��Bold"��� -�   $ label2��$��Server��$
��Left=�$��
10,236,0,0q�$	��Top=�$
��Bold"��� -�   $ label3��$��Server dekodirano��$
��Left=�$��496,236,0,0q�$	��Top=�$
��Bold"��� 
���   �$��1q�$
��Left=�$	��327��$��445,493,0,0q�$	��Top=�$��0���� -�   $ label4��$��Klijent��$
��Left=�$	��Top=�$��41��$��72��$��
ExtraBlack"�$��18(�$��1q�$ 3.583,3.024&�$��248,470,0,0q��� -�   $ label5��$��Server��$
��Left=�$��918,471,0,0q�$	��Top=�$��41��$��68��$��18(�$��
ExtraBlack"��� -�   $ textBox_info��$
��Left=�$	��372��$��
991,90,0,0q�$

 Wrap=�$	��Top=�$	��287�� . $
 Auto=�$
 Auto=����	#FF420C0C$��Consolas)� . 	 . �� -�   $ label50��$
��INFO��$
��Left=�$��
991,64,0,0q�$	��Top=�$
��Bold"�