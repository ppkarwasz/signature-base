rule EXPL_ODF_DBRange_Remote_ODB_CVE_2026_59265_Oct26 {
   meta:
      description = "Detects an OpenDocument spreadsheet with an auto-refreshing database range whose data source is a remote database document (ODB), as used to load attacker-controlled JDBC drivers in Apache OpenOffice and LibreOffice (CVE-2026-59265). Matches content.xml of ODS files or flat FODS files."
      author = "Piotr P. Karwasz"
      reference = "https://www.cve.org/CVERecord?id=CVE-2026-59265"
      date = "2026-10-01"
      score = 75
      hash1 = "97daed94ddff0cc3267f8deb11ceaf76ae2f9dc270307333d5e0fe47eadb7a07"
      id = "d5355005-453d-4660-89a8-6e81948288be"
   strings:
      $a1 = "<table:database-range " ascii
      $a2 = "table:refresh-delay=" ascii

      $r1 = /table:database-name="(https?|ftps?|webdavs?|smb):\/\// nocase ascii
      /* UNC paths: file://host/..., file:////host/... or backslashes */
      $r2 = /table:database-name="file:(\/\/[^\/"]|\/{4}|\\\\)/ nocase ascii
   condition:
      filesize < 20MB
      and all of ($a*)
      and 1 of ($r*)
}

rule EXPL_ODB_Remote_JDBC_ClassPath_CVE_2026_59265_Oct26 {
   meta:
      description = "Detects an OpenDocument database (ODB) whose JDBC driver class path points to a remote location, as used to load attacker-controlled JDBC drivers in Apache OpenOffice and LibreOffice (CVE-2026-59265). Matches content.xml of ODB files."
      author = "Piotr P. Karwasz"
      reference = "https://www.cve.org/CVERecord?id=CVE-2026-59265"
      date = "2026-10-01"
      score = 70
      hash1 = "aa2889d26859275455fa227ed731de04bba00da850c0b2d334b41a2e42a71762"
      id = "e7447d61-6732-4986-9183-544caec350b5"
   strings:
      $a1 = "<db:driver-settings" ascii

      $r1 = /db:java-classpath="[^"]{0,512}(https?|ftps?|webdavs?|smb):\/\// nocase ascii
      /* UNC paths: file://host/..., file:////host/... or backslashes */
      $r2 = /db:java-classpath="[^"]{0,512}file:(\/\/[^\/"]|\/{4}|\\\\)/ nocase ascii
   condition:
      filesize < 1MB
      and $a1
      and 1 of ($r*)
}
