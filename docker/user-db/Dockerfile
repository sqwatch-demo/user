FROM mongo:6.0.3
ADD ./scripts /tmp/scripts
ADD ./mongodb.conf /etc/mongodb.conf
# Modify child mongo to use /data/db-accounts as dbpath (because /data/db wont persist the build because it is already a VOLUME)
RUN mkdir -p /data/db-users \
    && chown -R mongodb:mongodb /data/db-users

RUN su - mongodb && mongod --fork --logpath /var/log/mongodb.log --dbpath /data/db-users  \
    && /tmp/scripts/mongo_create_insert.sh \
    && mongod --dbpath /data/db-users --shutdown \
    && chown -R mongodb /data/db-users

# Make the new dir a VOLUME to persist it
VOLUME /data/db-users

CMD ["mongod", "--config", "/etc/mongodb.conf" ]
