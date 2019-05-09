## Bitlocker šifrovánı́ disku v Linuxovém prostředı́

Diplomová práce zpracovávána na Fakultě aplikované informatiky UTB.

#### Obsah repozitáře

- **patches** -- patche pro UDisks a libblockdev přidávající podporu pro BitLocker zařízení
- **rpms** -- RPM balíčky pro Fedoru 30, obsahuje opatchované verze libblockdev a UDisks a nástroj bitlockersetup
- **slides** -- prezentace pro obhajobu a kontrolní dny
- **src** -- zdrojové kódy vytvořeného nástroje bitlockersetup
- **text** -- text práce a zdrojové soubory práce ve formátu LaTeX

#### Testování

Pro testování je doporučeno využít Fedoru 30 a přiložené RPM balíčky. Pro správné fungování UDisks je třeba util-linux ve verzi 2.33 nebo novější.

V současné době jsou podporována pouze BitLocker zařízení šifrována pomocí AES-XTS.
