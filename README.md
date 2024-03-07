Please note that this is work in progress. Gnark has fixed the main issue, which was an inability to manipulate 2D arrays. At the time of publishing, Gnark was still releasing the 2D array manipulation, now it has, and I am working on a better version of this implementation. See Gnark's Issue [#798](https://github.com/Consensys/gnark/issues/798)

# PhotoProof 

PhotoProof allows a photographer to sign an image (with a trusted camera) and define a set of permissible transformations that editors may be able to alter the image in an authorized manner. The signed original image and the set of permissible transformations are used to create a compliance predicate for a zk-SNARK proving and verifying mechanism for Image Authentication.

# My Implementation in Go
Unfortunately, gnark library is a nacent library and has limited support from the community and due to this, I was unable to apply all the transformations defined by Naveh at al. I was only able to implement the Identity transformation.

This was mainly due to gnark's inability to manipulate 2D arrays using the frontend.API in the Define() function. An example of this limitation is included, alongside a PhotoProof demonstration in Golang using the Identity transformation only.

# Running the Demo
To run the demo, simply navigate to `src` directory and type `go run main.go` once you have a Golang environment setup. This will take you through some of the operations conducted by the trusted camera, editors and verifiers.

# References

[1] Assa Naveh and Eran Tromer. Photoproof: Cryptographic image authentication for any set of permissible transformations. In 2016 IEEE Symposium on Security and Privacy (SP), pages 255–271, 2016.
