# TEMA 1 - Router Dataplane

## Prezentare

In acreasta tema am implementat dataplane-ul unui router care poate redirecta pachete IP, trata erori cu protocolul ICMP si sa descopere adrese MAC in mod dinamic prin cereri de tip ARP.

Topologia retelei testate a fost alcatuita din 4 entitati **host** si 2 tip **router**, care functioneaza conform implementarii:


 ```
 h0               h2
    \           /
     r0 - - - r1
    /           \
 h1               h3
 ```

## Workflow General

Routerul tine o bucla deschisa in care citeste de pe interfetele sale posibila primire a unui pachet. Dataplane-ul a fost implementat sa primeasca 3 categorii de pachete:

1. **IP** - Simple pacete cu informatie ce asteapta sa fie redirectate
2. **ARP** - Pachete cu referinta la distribuirea dinamica a adreselor MAC, ce pot fi de 2 feluri:
    1. **REQUEST** - Trimise direct de la un host cu rolul de a obtine adresa MAC a routerului
    2. **REPLY** - Trimise de un host in urma primirii unui broadcast ARP de la router in care este oferita adresa MAC.
3. **ICMP** - Subordonat tipului IP, aceste pachete sunt primite sub forma unui *ECHO REQUEST* de la un host pentru testarea conectivitatii.

### Pachete IP

In forma lor cea mai generala, router-ul va primi un pachet IP, ii va cauta in tabela de rutare urmatorul hop, in tabela arp adresa MAC aferenta urmatorului hop si il va trimite inapoi in retea. Din pacate, aceasta formula poate fi usor deturnata in cazul unor cazuri aparte, ce au fost tratate astfel:

- **TTL aproape de expirare** -> pachetul este aruncat
- **Date corupte (checksum gresit)** -> pachetul este aruncat
- **Tabela de rutare nu contine next hop** -> pachetul este aruncat
- **Tabela ARP nu contine adresa MAC dorita** -> este trimis un ARP request la adresa IP aferenta urmatorului hop, iar pachetul este salvat intr-o coada

TTL este actualizat si checksum-ul este recalculat in urma mdoficarii adreselor de sursa si destinatie, apoi pachetul este trimis in retea.

### Pachete ARP

Sunt generate in cazul unui *ARP Table miss* de catre router. Pachetele cu adresa MAC lipsa sunt tinute intr-o coada pana la descoperirea adresei necesare. Pentru a gasi adresa MAC, routerul trimite un pachet ARP cu adresa MAC tip broadcast si IP destinatie ca IP-ul pachetului initial si asteapta un raspuns de la fiecare entitate cu care are legatura pana gaseste adresa dorita.

Celelalte pachete ARP de gestionat sunt de tipul:

- **OP_REPLY** - routerul genereaza o noua intrare in tabela ARP si trece prin fiecare element al cozii de pachete salvate pana gaseste unul cu o adresa MAC potrivita. In acest caz, este scos din coada si tratat ca un pachet IP normal.

- **OP_REQUEST** - routerul modifica pachetul initial prin inversarea adresei de sursa cu cea de destinatie si modificand sursa ca fiind adresa lui (obtinuta de pe interfata de pe care a fost citit pachetul initial). Mai mult, router-ul va pune in pachet adresa lui MAC ca sa fie in mod universal vizibil host-ului.

### Pachete ICMP

Acest tip de pachete sunt folosite pentru a trimite inapoi mesaje de debugging sau pentru a asigura conectivitatea prin functionalitatea ***ECHO***. Ele sunt, de fapt, pachete IP cu un header ICMP si o modificare de tip in header-ul IP pentru a citi corect mesajul, astfel vor fi tratate in retea ca simple pachete IP.

Ele sunt create si trimise in 2 cazuri generale:

1. **ECHO** - in cazul in care un host trimite un pachet ICMP de tip ECHO pentru testarea comunicarii, adica adresa destinatie a pachetului este router-ul in sine. Routerul va schimba codul si tipul (0 si 0) al pachetului pentru a semnala host-ului un *ECHO REPLY*. Apoi, sursa si destinatia sunt schimbate ca sa se poata intoarce la host-ul initial. Din acest punct, este tratat ca un simplu pachet IP si este trimis inapoi in retea.

2. **EROARE** - poate sa apara in cele urmatoarele cazuri:
    1. **Host unreachable** - nu este gasit un next hop
    2. **Packet timeout** - a expirat TTL

    Cele 2 tipuri erori sunt distinse in functie de tip si cod, dar sunt tratate exact la fel. In cazul intalnirii unei astfel de erori, router-ul va extinde pachetul IP de baza in asa fel incat sa contina un header ICMP cu tipul, codul si checksum-ul aferent erorilor, dar si cu primii 64 de biti din header-ul IP al pachetului. Pe urma, header-ul IP este modificat in asa fel incat sa aiba sursa si destinatia necesare trimiterii inapoi la host si este redirectat in retea.

## Concluzii

Aceasta tema m-a ajutat sa inteleg cat de usor si compact putem trimite pachete de diverse tipuri si scopuri prin intermediul ethernet, intelegand ca router-ul din casa mea poate face mult mai multe decat credeam cu mult mai putin efort decat m-as fi asteptat.

Lucrand cu date atat de bine impachetate, e **FOARTE** usor sa ai o mica greseala de logica in trecerea din host si network order sau in gasirea unui cat gresit, etc. ce poate duce la un debugging lung si bun (mai ales ca reteaua m-a privat de dragul meu printf debugging), sau cel putin asa am intuit pentru ca eu sigur nu am facut debugging 2 ore pentru un cast gresit la verificarea pentru echo request hihi haha.

Am invatat foarte multe din tema asta si sper ca urmatoarele sa fie la fel de interesante ca aceasta.
