# Project Overview

## General

This project focuses on scalable network infrastructure management, providing a centralized approach while relying on a single self-managed service.

Key features include:

- **Improved Security:**  
  - No need for host network port forwarding.  
  - Host IP is no longer visible externally.  
  - Configurable whitelists, port forwarding, rate limiting, SYN flood protection, and ban lists on a per-server basis.

- **Live Analytics:**  
  The logging middleware for Nginx enables live analytics, allowing quick response to attacks or other server errors.

- **Custom Error Pages:**  
  - Inline editable error pages based on error code, page, and server.  
  - Display a page if the host does not respond within a certain time (proxy timeout).

- **Centralized SSL Management:**  
  Simplifies SSL certificate handling across all servers.

- **Self-Managed DNS System:**  
  Fully controlled nameserver for internal and external DNS resolution.

## Future Plans

- **Failsafe Mechanism:**  
  Automatic failover if a server goes down, the next server takes over.

- **Enhanced Security Features:**  
  Integration with Fail2Ban and other security-relevant measures.

- **Expanded Analytics:**  
  Additional analytics capabilities for marketing or other purposes.
