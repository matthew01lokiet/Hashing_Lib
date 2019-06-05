# Hashing_Lib
Hashing library written in C++ providing eight hashing functions from SHA and MD family:

-> std::string SHA0( std::string to_hash );

-> std::string SHA1( std::string to_hash );

-> std::string SHA224( std::string to_hash );

-> std::string SHA256( std::string to_hash );

-> std::string SHA384( std::string to_hash );

-> std::string SHA512( std::string to_hash );

-> std::string MD5( std::string to_hash );

-> std::string MD4( std::string to_hash );

namespace used -> "hash_lib"

Library includes full description.


Example how to use:
```
  #include <iostream>
  #include <iomanip>
  #include "hashing.h"

  using namespace std;

  int main()
  {
	  string test = "jeasigjeigjiejgirhkiosekseopgkesigesirhjerdighjrihjserihjesrighjsihgjesrighsjehojsejgiejiogjsiojgei";
  	try
	  {	
		  std::string test_SHA0   = hash_lib::SHA0(test);
		  std::string test_SHA1   = hash_lib::SHA1(test);
		  std::string test_SHA224 = hash_lib::SHA224(test);
		  std::string test_SHA256 = hash_lib::SHA256(test);
		  std::string test_SHA384 = hash_lib::SHA384(test);
		  std::string test_SHA512 = hash_lib::SHA512(test);
		  std::string test_MD5 	= hash_lib::MD5(test);
		  std::string test_MD4    = hash_lib::MD4(test);
		
		  cout<<endl<<endl;
		  cout<<"|"<<setfill('-')<<setw(150)<<"-"<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(84)<<" HASHING OUTPUT "<<setfill(' ')<<setw(67)<<"|"<<endl;
		  cout<<"|"<<setfill('-')<<setw(150)<<"-"<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
		
		  cout<<"|     MD4: "<<test_MD4.substr(0,16)<<" "<<test_MD4.substr(16,16)<<setfill(' ')<<setw(108)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
  		
	  	cout<<"|     MD5: "<<test_MD5.substr(0,16)<<" "<<test_MD5.substr(16,16)<<setfill(' ')<<setw(108)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
		
		  cout<<"|    SHA0: "<<test_SHA0.substr(0,16)<<" "<<test_SHA0.substr(16,16)<<" "
  						<<test_SHA0.substr(32,8)<<setfill(' ')<<setw(99)<<"|"<<endl;
	  	cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
		
		  cout<<"|    SHA1: "<<test_SHA1.substr(0,16)<<" "<<test_SHA1.substr(16,16)<<" "
			  			<<test_SHA1.substr(32,8)<<setfill(' ')<<setw(99)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
		
		  cout<<"| SHA-224: "<<test_SHA224.substr(0,16)<<" "<<test_SHA224.substr(16,16)<<" "
			  			 <<test_SHA224.substr(32,16)<<" "<<test_SHA224.substr(48,8)
				  		 <<setfill(' ')<<setw(82)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
		
		  cout<<"| SHA-256: "<<test_SHA256.substr(0,16)<<" "<<test_SHA256.substr(16,16)<<" "
			  			 <<test_SHA256.substr(32,16)<<" "<<test_SHA256.substr(48,16)
				  		 <<setfill(' ')<<setw(74)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
						 
		  cout<<"| SHA-384: "<<test_SHA384.substr(0,16)<<" "<<test_SHA384.substr(16,16)<<" "
			  			 <<test_SHA384.substr(32,16)<<" "<<test_SHA384.substr(48,16)<<" "
				  		 <<test_SHA384.substr(64,16)<<" "<<test_SHA384.substr(80,16)
					  	 <<setfill(' ')<<setw(40)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
						 
		  cout<<"| SHA-512: "<<test_SHA512.substr(0,16)<<" "<<test_SHA512.substr(16,16)<<" "
			  			 <<test_SHA512.substr(32,16)<<" "<<test_SHA512.substr(48,16)<<" "
				  		 <<test_SHA512.substr(64,16)<<" "<<test_SHA512.substr(80,16)<<" "
					  	 <<test_SHA512.substr(96,16)<<" "<<test_SHA512.substr(112,16)
						   <<setfill(' ')<<setw(6)<<"|"<<endl;
		  cout<<"|"<<setfill(' ')<<setw(151)<<"|"<<endl;
		
		  cout<<"|"<<setfill('-')<<setw(151)<<"|"<<endl;


	  }
	  catch(...)
	  {
		  cout<<"Something went wrong"<<endl;
	  }	
	  return 0;
  }
  ```
  Thinking about adding SHA3 family in future, who knows...
  
