# **Einrichtung des Hexbeet‑Servers**

Der **Hexbeet‑Server** nutzt drei Komponenten, um die Blacklist des Hexbeets zu umgehen: eine **DNS‑Weiterleitung**, einen **Webserver** und ein **selbstsigniertes SSL‑Zertifikat**.

Dieses Tool kombiniert alle drei Möglichkeiten, um eurem lokalen VRChat eine falsche Blacklist unterzuschieben. Diese Änderung gilt nur für euer System — jeder muss sie also für sich selbst einrichten.

<div style="border-left:4px solid #c00;background:#ffe6e6;padding:12px;margin:12px 0;">
**WARNUNG**

Es ist zwar möglich, dass eine Person diesen Server öffentlich laufen lässt und mehrere andere Personen ihn nutzen. Das stellt aber ein hohes **Sicherheitsrisiko** dar.

Das Tool ist so entworfen, dass für jeden Benutzer eine eigene Root‑CA generiert wird. Wenn jemand anders diese Datei hat, kann er die Sicherheit eures HTTPS‑Systems untergraben. Deshalb: **Gebt die Dateien aus dem `Certs`‑Ordner auf keinen Fall an andere weiter!**

</div>

<div style="border-left:4px solid #aa8000;background:#fff4cc;padding:12px;margin:12px 0;">
**Hinweis**

Dieses Tool nutzt einen Webserver auf den Ports **80** und **443**. Wenn ihr bereits einen Webserver betreibt, könnt ihr das Tool in dieser Form nicht parallel starten. Ihr könnt das Tool aber weiterhin verwenden, um SSL‑Zertifikate zu erzeugen und diese mit einem anderen Server zu benutzen.

</div>

---

## **1) Einrichtung des Webservers**

1. Ladet euch das Release **DEPSERV** herunter: [DEPSERV Releases auf GitHub](https://github.com/WeslieDE/DEBSERV/releases/latest).
2. Entpackt das ZIP‑Archiv `debserv.zip`.
3. In diesem Archiv befindet sich eine `Config.json`. Öffnet sie in einem Editor und ersetzt den Inhalt mit dieser Beispielkonfiguration: [Beispiel‑Config (Gist)](https://gist.github.com/WeslieDE/e8b2ab94265d5fba1311974cc47c4048).
4. Startet `debserv.exe`. Nach einigen Sekunden sollte eine Meldung wie `"[HTTPS] Läuft auf https://0.0.0.0:443"` erscheinen. Ihr könnt das Tool danach wieder schließen.
5. Es wurde jetzt ein Ordner `Certs` generiert, in dem mehrere Zertifikate liegen. Darin sollte auch eine Datei `RootCA.pem` vorhanden sein.

> Hinweis: Wenn ihr einen anderen Webserver verwendet, könnt ihr trotzdem die erzeugten Zertifikate weiterverwenden.

---

## **2) Importieren der Root‑CA**

Damit Windows (oder Linux) — und damit auch VRChat — eure Zertifikate akzeptiert, müsst ihr die neu generierte Root‑CA importieren:

> 1. Drückt **Win + R** → `mmc` eingeben.
> 2. Datei → "Snap‑In hinzufügen/entfernen…" → **Zertifikate** → **Hinzufügen**.
> 3. Wenn Fragen erscheinen: immer **Weiter** / **Fertig stellen** klicken.
> 4. Navigiert links: **Zertifikate (Lokaler Computer)** → **Vertrauenswürdige Stammzertifizierungsstellen** → **Zertifikate**.
> 5. Rechtsklick **Zertifikate** → **Alle Aufgaben** → **Importieren…** → Datei `./Certs/RootCA.pem` auswählen → **Weiter** → **Fertig stellen**.

<div style="border-left:4px solid #aa8000;background:#fff4cc;padding:12px;margin:12px 0;">
**Hinweis**

Sichert euch `rootCA.pem` und `rootCA.key`. Es ist nicht empfehlenswert, viele verschiedene Root‑CAs zu importieren. Ihr könnt diese Dateien bei Bedarf wiederverwenden, auch wenn ihr das Tool neu installiert.

</div>

---

## **3) Einrichtung der DNS‑Weiterleitung**

Als Nächstes müsst ihr die DNS‑Weiterleitung konfigurieren. Eine Videoanleitung dazu (Windows) findet ihr hier: [DNS‑Weiterleitung (Videoanleitung)](https://www.youtube.com/watch?v=-2yMGQo_a9A).

In die Hosts‑Datei fügt ihr am Ende Folgendes hinzu (kopierbar):

> 127.0.0.1 umbra999.github.io
> 
> 127.0.0.1 beetperms.github.io


