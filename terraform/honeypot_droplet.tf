resource "digitalocean_ssh_key" "sensor_key" {
  name       = "cowrie-sensor"
  public_key = file("../.ssh/honeypot.pub")
}
resource "digitalocean_droplet" "sensor" {
  name       = "cowrie-sensor-01"
  region     = "nyc1"
  size       = "s-1vcpu-1gb"
  image      = "ubuntu-22-04-x64"
  ssh_keys   = [digitalocean_ssh_key.sensor_key.id]
  monitoring = true
  user_data  = <<-EOF
              package_update: true
              package_upgrade: true
              packages:
                - docker.io
                - docker-compose
              runcmd:
                - usermod -aG docker root
                - systemctl enable docker
                - systemctl start docker
              EOF
}
resource "digitalocean_firewall" "sensor_fw" {
  name = "sensor-firewall"
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "2222"
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
  droplet_ids = [digitalocean_droplet.sensor.id]
}
output "sensor_ip" {
  value = digitalocean_droplet.sensor.ipv4_address
}
