/*
 * Aegis bundled YARA rules - defensive triage of self-extracting JS loaders.
 * These rules are intentionally broad heuristics; they match the family of
 * packers we have observed in obfuscated abuse toolkits.
 */

rule Aegis_JS_SelfExtract_TmpRequire
{
    meta:
        author = "aegis"
        severity = "high"
        description = "JS that writes a .tmp_*.js sibling, requires it, then unlinks"
    strings:
        $a = ".tmp_${" ascii
        $b = "writeFileSync" ascii
        $c = "unlinkSync" ascii
        $d = "require(" ascii
    condition:
        all of them
}

rule Aegis_JS_AntiDebug_NodeOptions
{
    meta:
        author = "aegis"
        severity = "medium"
        description = "JS that bails out when node --inspect / NODE_OPTIONS is set"
    strings:
        $a = "process.execArgv" ascii
        $b = "NODE_OPTIONS" ascii
        $c = "inspect" ascii
    condition:
        all of them
}

rule Aegis_JS_Crypto_Aes256Gcm_With_Gunzip
{
    meta:
        author = "aegis"
        severity = "high"
        description = "JS payload decrypted with aes-256-gcm and then gunzipped at runtime"
    strings:
        $a = "createDecipheriv('aes-256-gcm'" ascii
        $b = "createDecipheriv(\"aes-256-gcm\"" ascii
        $c = "gunzipSync" ascii
    condition:
        ($a or $b) and $c
}
