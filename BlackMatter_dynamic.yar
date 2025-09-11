rule BlackMatter_2025_dynamic
{
meta:
	author = "Kevin Johnson"
    type = "To be run in memory"
    description = "Identifies BlackMatter ransomware, based on a sample from September 2025"
    sample_sha256 = "374f9df39b92ccccae8a9b747e606aebe0ddaf117f8f6450052efb5160c99368"

strings:
	$put_rsa_dword_in_chacha_matrix = { 81 ?? FF FF FF 00 // and {reg}, 0FFFFFFh
                                        89 ?? 7C          // mov [{reg}+7Ch], reg
                                        B? 78 00 00 00    // mov {reg}, 120 
                                        69 ?? 05 84 08 08 // imul {reg}, 8088405h 
                                        4?                // inc {reg}
                                        f7                // mul {reg}
                                    } /* Code seen in a custom ChaCha implementation from BlackMatter */

    $constants_in_prng = { 68 2D F4 51 58  // push    5851F42Dh
                           68 2D 7F 95 4C  // push    4C957F2Dh 
    } /* Constants used in a PRNG function BlackMatter uses. This is a known PRNG function, can be in benign files. Put in to improve YARA performance (Can eliminate more files as candidates more quickly)*/

    // Both of these belong to shellcode which is decrypted and called dynamically by BlackMatter fairly early in it's setup
condition:
	all of them
}
