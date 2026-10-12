set -u
cd sdks/php-pca && rm -rf infection-out
composer install --no-interaction --no-progress -q 2>&1 | tail -3
# Infection is not a declared dev dependency (keeps the SDK's dev tree small): add it to this PRIVATE job copy only.
test -x vendor/bin/infection || { composer config --no-interaction allow-plugins.infection/extension-installer true; composer require --dev --no-interaction --no-progress -q -W "infection/infection:^0.29" 2>&1 | tail -5; }
# coverage driver: pcov (installed on demand; not every box image has it)
php -m | grep -qiE "pcov|xdebug" || flock /tmp/php-pcov-install.lock sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y -q php-pcov >/dev/null 2>&1 || true
php -m | grep -iE "pcov|xdebug"; command -v phpdbg
if php -m | grep -qiE "pcov|xdebug"; then R="php"; else R="phpdbg -qrr"; fi
echo "runner=$R threads=${T:-6}"
$R vendor/bin/infection --threads=${T:-6} --no-progress --min-msi=0 --min-covered-msi=0 2>&1 | tail -25
php -r '$d=json_decode(file_get_contents("infection-out/log.json"),true); $o=["stats"=>$d["stats"]]; foreach(["escaped","uncovered","timeouted","errored"] as $k){$o[$k]=array_map(fn($m)=>["file"=>basename($m["mutator"]["originalFilePath"]),"line"=>$m["mutator"]["originalStartLine"],"mutator"=>$m["mutator"]["mutatorName"],"diff"=>$m["diff"]],$d[$k]??[]);} file_put_contents("infection-out/summary.json", json_encode($o, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));'
ls -la infection-out
# survivors (escaped + uncovered) vs the equivalents ledger: every survivor ledgered, no stale php-pca entry
cd ../.. && python3 tools/pca-audit/native-mutation/php-survivors.py sdks/php-pca/infection-out/summary.json sdks/php-pca/src sdks/php-pca/infection-out/survivors.json && node tools/pca-audit/native-check-equivalents.mjs sdks/php-pca/infection-out/survivors.json
