data "digitalocean_ssh_key" "existing_key" {
  name = "cowrie-sensor"
}

resource "digitalocean_droplet" "blocklist" {
  name       = "aegis-blocklist-01"
  region     = "nyc1"
  size       = "s-1vcpu-1gb"
  image      = "ubuntu-22-04-x64"

  ssh_keys   = [data.digitalocean_ssh_key.existing_key.id]

  monitoring = true

  user_data  = <<-EOF
              #cloud-config
              package_update: true
              package_upgrade: true
              packages:
                - python3-pip
                - python3-venv
                - sqlite3
                - cron
                - nginx
              runcmd:
                - systemctl enable nginx
                - systemctl start nginx
                - mkdir -p /var/www/html/threatintel
                - chown -R www-data:www-data /var/www/html/threatintel
              EOF
}

resource "digitalocean_firewall" "blocklist_fw" {
  name = "blocklist-firewall"

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["89.187.170.169/32"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0"]
  }

  droplet_ids = [digitalocean_droplet.blocklist.id]
}

output "blocklist_server_ip" {
  value = digitalocean_droplet.blocklist.ipv4_address
}