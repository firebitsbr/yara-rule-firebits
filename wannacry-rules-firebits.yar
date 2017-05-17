rule wannacry : wannacry wannacrypt windows ransoware
{
meta:
	author = "Mauro Risonho de Paula Assumpção, firebits, mauro.risonho@gmail.com"
	date = "2017-05-17 11:12 UTC"
	description = "WannaCry is a crypto-ransomware that affects the Microsoft Windows operating system."
	hash0 = "84c82835a5d21bbcf75a61706d8ab549"
	hash1 = "f351e1fcca0c4ea05fc44d15a17f8b36"
	hash2 = "509c41ec97bb81b0567b059aa2f50fe8"
	hash3 = "82fd8635ff349f2f0d8d42c27d18bcb7"
	sample_filetype = "exe"
strings:
	$string0 = ".sqlitedb" wide
	$string1 = "SeAlNrZbE"
	$string2 = "2@YAPAXI@Z"
	$string3 = "TbFwZiK"
	$string4 = "XhHpSeA"
	$string5 = "RRvM;;"
	$string6 = "4$8,9-6'.6$:"
	$string7 = "Microsoft Enhanced RSA and AES Cryptographic Provider"
	$string8 = ".onetoc2" wide
	$string9 = "attrib "
	$string10 = ".class" wide
	$string11 = "SbE\\lHtQeF"
	$string12 = "advapi32.dll"
	$string13 = "UUPx(("
	$string14 = "1hHpXeA"
	$string15 = "p\\lHtW"
	$string16 = "Microsoft" wide
	$string17 = "aaj_55"
condition:
	17 of them
}
