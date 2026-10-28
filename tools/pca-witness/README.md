# pca-witness

Reference transparency-log witness (see the "Operate a ledger witness" guide in the PCA documentation). Source for the
container image; the guide is the user-facing reference.

    npm test                                  vitest (needs the PCA library source next to it)
    docker build -f tools/pca-witness/Dockerfile -t pca-witness .      from the repository root
    tools/pca-witness/e2e.sh                  build the image and run a cosign round trip against the container
