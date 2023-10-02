Super Secure ATM Mail
Designul actual al serverului de e-mail al ATM nu este optim, fiind prezente întârzieri dese în trimiterea email-urilor sau probleme cu repetarea acelorași email-uri. Însă, cea mai importantă problemă este componenta de securitate care nu este implementată corespunzător.
Scopul acestei teme este să implementați o aplicație, folosind API-ul OpenSSL și limbajul C++, prin care să se poată crea email-uri și pachete specifice protocolului NSMTP (New SMTP).
Structura unui email va avea următoarea formă:
EMAIL ::= SEQUENCE {
	From		PRINTABLE STRING,
	To		PRINTABLE STRING,
	Title		PRINTABLE STRING,
	Body		PRINTABLE STRING,
	Signature	OCTET STRING,
	Time 		UTCTime,
	Encoded_Key PRINTABLE STRING
}
Aplicația va pune la dispoziție posibilitatea înrolării unui nou utilizator în baza de date a serverului de e-mail. La înrolarea fiecărui user, acestuia i se vor defini și anumiți parametri criptografici. După crearea utilizatorului, parametrii acestuia nu se mai modifica (chei simetrice, asimetrice, chei de sesiune etc.) și vor fi salvați într-un fișier specific cu o denumire de forma [user]-params.crypto (un exemplu de asemenea fișier este prezentat la finalul enunțului). De asemenea, baza de date a serverului va mai conține și un fișier denumit key-pubs.txt ce va stoca căile absolute către fișierele ce conțin cheile publice ale utilizatorilor.
Fiecare cont de email va fi simulat prin prezența unui fișier pe disk cu o denumire de forma: [Nume-prenume.account] în care vor fi stocate, sub forma de hex string și pe câte o linie distinctă, e-mail-urile primite de către utilizatorul respectiv.
Conținutul fiecărui email va fi criptat folosind o variantă a algoritmului AES-GCM. Cheia va fi derivată folosind PBKDF2 cu HMAC-SHA-256, pornind de la cheia simetrică definită în parametrul de cheie simetrică din fișierul cu parametrii criptografici. În final, se compune câmpul Body (din structura unui e-mail prezentată anterior, în format ASN.1) ca un blob de forma:
Base64 ( [ IV  || Ciphertext_GCM  || TAG_GCM] )
unde IV = Nonce xor Timestamp, nonce-ul regăsindu-se în fișierul cu parametrii criptografici, iar timestamp reprezintă momentul de timp când se efectuează criptarea.
Fiecare câmp Body va fi semnat de expeditorul e-mail-ului folosind o pereche de chei RSA pe 4096 de biți, iar semnătura va constitui câmpul Signature (din structura unui e-mail prezentată anterior, în format ASN.1). Cheia RSA a fiecărui utilizator se creează în momentul înregistrării utilizatorului și va avea exponentul public egal cu cel mai mic număr liber de pătrate, impar, multiplu de 7 și mai mare decât momentul de timp din momentul înregistrării. Cheile RSA (publică și privată) se salvează în fișiere de tipul [user]-key.prv, respectiv [user]-key.pub, căile absolute către acestea fiind definite în fișierul cu parametrii criptografici.
Câmpul Encoded Key (din structura unui e-mail prezentată anterior, în format ASN.1) se generează prin criptarea, cu cheia publică a destinatarului, a cheii derivate simetrice folosită de AES-GCM la criptarea mesajului.
Celelalte câmpuri din structura unui e-mail prezentată anterior, în format ASN.1, reprezintă:
Câmpul From - numele expeditorului e-mail-ului;
Câmpul To - numele destinatarului e-mail-ului;
Câmpul Title - denumirea e-mail-ului, introdusă de către expeditor;
Câmpul Time - momentul de timp la care se trimte e-mail-ul.

Aplicația va pune la dispoziție o funcție pentru crearea de mesaje prin citirea acestora de la tastatură și salvarea structurii e-mail-ului în fișierul specific fiecărui destinatar. De asemenea, aplicația va oferi și posibilitatea citirii unui email, prin transmiterea ca parametru a unui index (numărul liniei unde este salvat emailul și afișarea acestuia pe ecran).
