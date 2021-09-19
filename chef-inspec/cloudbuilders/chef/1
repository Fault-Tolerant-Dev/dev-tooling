ARG CB_PROJECT_ID
FROM gcr.io/${CB_PROJECT_ID}/docker

#Install Chef Workstation
RUN set -eux && \
    curl -o chef-workstation.deb https://packages.chef.io/files/stable/chef-workstation/21.2.303/debian/10/chef-workstation_21.2.303-1_amd64.deb && \
    dpkg -i chef-workstation.deb && \
    rm  chef-workstation.deb
RUN /bin/bash -c "chef env --chef-license=accept-silent" 
