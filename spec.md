
## Key Exchange stage

###Client request

    +--------------+----------------+------------+------------+----------------+----------+
    | Request Type | Request Length | Time Stamp | Client Key | Authentication | Padding  |
    +--------------+----------------+------------+------------+----------------+----------+
    |       1      |       2        |     4      |  Variable  |       32       | Variable |
    +--------------+----------------+------------+------------+----------------+----------+

Request Type: 10

Time Stamp: struct.pack('>I', int(time.time()))

Client Key: ECDH key for key exchange, the first byte indicates the length.

Authentication: HMAC-SHA256 key is the user password, input is the time-stamp + client Key + client user name. Server should be able to identify the user.

Padding: random length padding.

###Server response

    +-----------------+---------------+----------------+------ ---+
    | Response Length | Response Code | Authentication | Padding  |
    +-----------------+---------------+----------------+----------+
    |        2        |       1       |    Variable    | Variable |
    +-----------------+---------------+----------------+----------+

Response Length: the length of response code, authentication and padding all together.

Response Code: 0x0 for success, others for failed.

Authentication: if authentication failed, this part is empty. if succeed, the authentication part is like this:

    +-------------------+---------------------------+------------------+------------+----------------+--------------------+-----------+
    | Server Key Length | Server Certificate Length | Signature Length | Server Key | Authentication | Server Certificate | Signature |
    +-------------------+---------------------------+------------------+------------+----------------+--------------------+-----------+
    |         1         |          1                |        1         |  Variable  |       32       |      Variable      |  Variable |
    +-------------------+---------------------------+------------------+------------+----------------+--------------------+-----------+

Server Key: for ECDH key exchange, the first byte indicates the length.

Authentication: HMAC-SHA256 key is the user password, input is the Client key + Server Key + Client user name, shows server have identified the user.

Server Certificate: Server public key, identifies the server, so others cannot pretend to be. the first byte indicates the length.

Signature: server signs the Authentication with Server Certificate private key. the first byte indicates the length.

Data transfered in handshake stage is encrypted with a pre-shared key, like behaved in shadowsocks.

By default, the pre-shared key is empty string, which is not a problem(TLS send those in plain-text).

At this stage, the client-side and server-side exchanged a encryption key for further use.

If the client-side already have a exchanged key, this step can be ignored.

## Connect Request

### Client Request

    +--------------+---------------+----------------+-------------------+---------+
    | Request Type | Client Key ID | Request Length | Real Request Addr |   MAC   |
    +--------------+---------------+----------------+-------------------+---------+
    |       1      |       16      |        2       |	   Variable     |    16   |
    +--------------+---------------+----------------+-------------------+---------+

Request Type: 11 for creating a new connection

Client Key ID: md5 digest for Client Key, identifies the user.

Length: the length of Real Request Addr

Request Type, Client Key ID and Length is encrypted with pre-shared key, while Real Request Addr is encrypted with exchanged key.

Real Request Addr:

    +------------+----------+------+----------+
    | Time Stamp | Hostname | Port | Padding  |
    +------------+----------+------+----------+
    |      4     | Variable |  2   | Variable |
    +------------+----------+------+----------+

the first byte of Hostname indicates the length.

MAC: the of MAC is truncated to leftmost 128 bits (16 bytes) according to RFC 2104.

### Server Response

Once connected, server should respond with follows.

    +-----------------+----------+
    | Response Length | Response |
    +-----------------+----------+
    |        2        | Variable |
    +-----------------+----------+

Response Length: length of response, encrypted with pre-shared key.

Response: encrypted with exchanged key, different from t


## Forward

The structure of a data chunk is shown below:

    +----------+----------+----------+
    | DATA.LEN |   DATA   |    MAC   |
    +----------+----------+----------+
    |     2    | Variable | Variable |
    +----------+----------+----------+

DATA.LEN is encrypted with pre-shared key. When DATA.LEN is 0, this connection is closed.

The DATA part is encrypted with exchanged key, structure is shown below:

    +-------------+----------+----------+
    | PADDING.LEN |   DATA   |  PADDING |
    +-------------+----------+----------+
    |      1      | Variable | Variable |
    +-------------+----------+----------+

If PADDING.LEN is smaller than 8, the whole data part should be considered fake, and discarded.

If PADDING.LEN equals 1, the other side should respond with a fake chunk. To avoid problem, only server side can request a fake chunk.
