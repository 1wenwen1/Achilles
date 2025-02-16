#ifndef Nonce_H
#define Nonce_H


#include "config.h"
#include "types.h"

#include <openssl/sha.h>
#include <string>

#include "salticidae/stream.h"


// typedef std::array<unsigned char,RANDOM_NUMBER_LENGTH> noncearray;

class Nonce {
 private:
  unsigned char nonce[RANDOM_NUMBER_LENGTH];
  //unsigned char hash[SHA256_DIGEST_LENGTH];
  bool set; // true if the hash is not the dummy hash

 public:
  Nonce();
  Nonce(bool b);
  Nonce(unsigned char nonce[RANDOM_NUMBER_LENGTH]);
  Nonce(bool b, unsigned char nonce[RANDOM_NUMBER_LENGTH]);
  Nonce(salticidae::DataStream &data);

  void serialize(salticidae::DataStream &data) const;
  void unserialize(salticidae::DataStream &data);

  bool getSet();
  unsigned char* getNonce();
  bool isDummy(); // true if the hash is not set
  bool isZero();

  std::string prettyPrint();
  std::string toString();

  bool operator==(const Nonce& s) const;
};


#endif