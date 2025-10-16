powerview "$DOMAIN"/"$USER":"$PASSWORD"@"$TARGET" --use-ldap
powerview "$DOMAIN"/"$USER":"$PASSWORD"@"$TARGET" --use-ldaps
powerview "$DOMAIN"/"$USER":"$PASSWORD"@"$TARGET" --use-gc
powerview "$DOMAIN"/"$USER":"$PASSWORD"@"$TARGET" --use-gc-ldaps
powerview "$DOMAIN"/"$USER"@"$TARGET" -H "$NT_HASH" 
powerview "$TARGET" --pfx "$USER".pfx
powerview "$DOMAIN"/"$USER":"$PASSWORD"@"$TARGET" --web --web-port 3000
