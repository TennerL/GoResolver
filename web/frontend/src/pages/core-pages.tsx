import { Alert, Badge, Button, Code, Container, Modal, NativeSelect, Paper, PasswordInput, SimpleGrid, Stack, Table, Text, TextInput, Textarea, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { ActionForm, EmptyState, PageHeader, StatusBadge } from "../common";
import { IconAlertCircle, IconDatabase, IconEdit, IconPlus, IconShieldLock, IconTrash } from "@tabler/icons-react";
import { useMemo, useState } from "react";

export function LoginPageView({ page }) {
  return (
    <Container size="xs" py="12vh">
      <Paper radius="xl" p="xl" className="hero-panel">
        <Stack gap="lg">
          <div>
            <Text size="xs" fw={700} tt="uppercase" c="dimmed">Secure Access</Text>
            <Title order={1}>GoResolver</Title>
            <Text c="dimmed">Sign in to manage domains, traffic controls, certificates, and system policy.</Text>
          </div>
          {page.Data?.Error ? <Alert color="red" icon={<IconAlertCircle size={16} />} title="Authentication failed">{page.Data.Error}</Alert> : null}
          <form method="post" action="/login">
            <Stack gap="md">
              <TextInput label="Username" name="username" required />
              <PasswordInput label="Password" name="password" required />
              <Button type="submit" fullWidth leftSection={<IconShieldLock size={16} />}>Login</Button>
            </Stack>
          </form>
        </Stack>
      </Paper>
    </Container>
  );
}

export function DashboardPageView({ page }) {
  const items = Array.isArray(page.Data) ? page.Data : [];
  const servers = Array.isArray(page.Servers) ? page.Servers : [];
  return (
    <Container fluid>
      <PageHeader title="System Overview" description="Live visibility into resolver health and managed server reachability." />
      <SimpleGrid cols={{ base: 1, md: 2, xl: 3 }} spacing="lg">
        {items.map((item) => <SummaryCard key={`item-${item.Name}`} label="System Check" title={item.Name} meta={null} status={item.Status} />)}
        {servers.map((server) => <SummaryCard key={`server-${server.ID}`} label="Managed Server" title={server.Name} meta={server.IP || "No IP assigned"} status={server.Status} />)}
      </SimpleGrid>
    </Container>
  );
}

function SummaryCard({ label, title, meta, status }) {
  return (
    <Paper radius="xl" p="lg" className="soft-panel">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "start", gap: 12 }}>
        <div>
          <Text c="dimmed" size="sm">{label}</Text>
          <Title order={4}>{title}</Title>
          {meta ? <Code className="code-chip">{meta}</Code> : null}
        </div>
        <StatusBadge status={status} />
      </div>
    </Paper>
  );
}

export function DomainsPageView({ page }) {
  const [opened, { open, close }] = useDisclosure(false);
  const items = Array.isArray(page.Data) ? page.Data : [];
  return (
    <Container fluid>
      <PageHeader title="Domains" description="Manage domains and jump directly into their record sets." actions={<Button leftSection={<IconPlus size={16} />} onClick={open}>Add Domain</Button>} />
      <Paper radius="xl" p="md" className="soft-panel">
        {items.length === 0 ? <EmptyState title="No domains yet" description="Create the first zone and the record management flow will appear here." /> : (
          <Table.ScrollContainer minWidth={760}>
            <Table highlightOnHover verticalSpacing="sm">
              <Table.Thead><Table.Tr><Table.Th>ID</Table.Th><Table.Th>Domain</Table.Th><Table.Th>Status</Table.Th><Table.Th>Actions</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {items.map((domain) => (
                  <Table.Tr key={domain.ID}>
                    <Table.Td><Code className="code-chip">{domain.ID}</Code></Table.Td>
                    <Table.Td fw={600}>{domain.Name}</Table.Td>
                    <Table.Td><StatusBadge status={domain.Status || "Unknown"} /></Table.Td>
                    <Table.Td>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <Button component="a" href={`/domains/${domain.ID}/records`} size="xs" variant="light" leftSection={<IconDatabase size={14} />}>Records</Button>
                        <ActionForm action={`/domains/${domain.ID}/delete`} fields={{}} confirmMessage="Delete this domain?"><Button type="submit" size="xs" color="red" variant="subtle" leftSection={<IconTrash size={14} />}>Delete</Button></ActionForm>
                      </div>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      <Modal opened={opened} onClose={close} title="Add Domain" centered>
        <form method="post" action="/domains/new">
          <Stack><TextInput name="name" label="Domain" placeholder="example.com" required /><Button type="submit">Save Domain</Button></Stack>
        </form>
      </Modal>
    </Container>
  );
}

export function RecordsPageView({ page }) {
  const [opened, { open, close }] = useDisclosure(false);
  const [mode, setMode] = useState("create");
  const [record, setRecord] = useState({ id: "", name: "", type: "A", content: "", ttl: "3600" });
  const records = Array.isArray(page.Data) ? page.Data : [];
  const startCreate = () => { setMode("create"); setRecord({ id: "", name: "", type: "A", content: "", ttl: "3600" }); open(); };
  const startEdit = (current) => { setMode("edit"); setRecord({ id: String(current.ID), name: current.Name, type: current.Type, content: current.Content, ttl: String(current.Ttl) }); open(); };
  return (
    <Container fluid>
      <PageHeader title="Records" description="Maintain DNS records without the old template duplication." actions={<Button leftSection={<IconPlus size={16} />} onClick={startCreate}>Add Record</Button>} />
      <Paper radius="xl" p="md" className="soft-panel">
        {records.length === 0 ? <EmptyState title="No records yet" description="Create the first record in this zone to start publishing DNS data." /> : (
          <Table.ScrollContainer minWidth={980}>
            <Table highlightOnHover verticalSpacing="sm">
              <Table.Thead><Table.Tr><Table.Th>ID</Table.Th><Table.Th>Name</Table.Th><Table.Th>Type</Table.Th><Table.Th>Content</Table.Th><Table.Th>TTL</Table.Th><Table.Th>Actions</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {records.map((item) => (
                  <Table.Tr key={item.ID}>
                    <Table.Td><Code className="code-chip">{item.ID}</Code></Table.Td>
                    <Table.Td fw={600}>{item.Name}</Table.Td>
                    <Table.Td><Badge variant="light">{item.Type}</Badge></Table.Td>
                    <Table.Td maw={420} style={{ whiteSpace: item.Type === "TXT" ? "normal" : "nowrap" }}>{item.Content}</Table.Td>
                    <Table.Td>{item.Ttl}</Table.Td>
                    <Table.Td>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <Button type="button" size="xs" variant="light" leftSection={<IconEdit size={14} />} onClick={() => startEdit(item)}>Edit</Button>
                        <ActionForm action={`/records/${item.ID}/delete`} fields={{}} confirmMessage="Delete this record?"><Button type="submit" size="xs" color="red" variant="subtle" leftSection={<IconTrash size={14} />}>Delete</Button></ActionForm>
                      </div>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      <Modal opened={opened} onClose={close} title={mode === "create" ? "Add Record" : "Edit Record"} centered>
        <form method="post" action={mode === "create" ? `/domains/${page.DomainID}/records/new` : `/records/${record.id}/edit`}>
          <Stack>
            <TextInput label="Record Name" name="name" value={record.name} onChange={(event) => setRecord((current) => ({ ...current, name: event.currentTarget.value }))} required />
            <NativeSelect label="Type" name="type" data={["A", "AAAA", "CNAME", "MX", "TXT", "TLSA"]} value={record.type} onChange={(event) => setRecord((current) => ({ ...current, type: event.currentTarget.value }))} />
            <Textarea label="Content" name="content" value={record.content} onChange={(event) => setRecord((current) => ({ ...current, content: event.currentTarget.value }))} minRows={3} required />
            <TextInput label="TTL" type="number" name="ttl" value={record.ttl} onChange={(event) => setRecord((current) => ({ ...current, ttl: event.currentTarget.value }))} />
            <Button type="submit" disabled={!record.name || !record.content}>Save Record</Button>
          </Stack>
        </form>
      </Modal>
    </Container>
  );
}

export function ServersPageView({ page }) {
  const [opened, { open, close }] = useDisclosure(false);
  const servers = Array.isArray(page.Data) ? page.Data : [];
  return (
    <Container fluid>
      <PageHeader title="Servers" description="Manage resolver targets and jump into per-server configuration." actions={<Button leftSection={<IconPlus size={16} />} onClick={open}>Add Server</Button>} />
      <Paper radius="xl" p="md" className="soft-panel">
        {servers.length === 0 ? <EmptyState title="No servers connected" description="Add a server to configure VPN access, reverse proxy rules, and protection policies." /> : (
          <Table.ScrollContainer minWidth={860}>
            <Table highlightOnHover verticalSpacing="sm">
              <Table.Thead><Table.Tr><Table.Th>ID</Table.Th><Table.Th>Name</Table.Th><Table.Th>IP</Table.Th><Table.Th>Status</Table.Th><Table.Th>Actions</Table.Th></Table.Tr></Table.Thead>
              <Table.Tbody>
                {servers.map((server) => (
                  <Table.Tr key={server.ID}>
                    <Table.Td><Code className="code-chip">{server.ID}</Code></Table.Td>
                    <Table.Td fw={600}>{server.Name}</Table.Td>
                    <Table.Td><Code className="code-chip">{server.IP}</Code></Table.Td>
                    <Table.Td><StatusBadge status={server.Status || "Unknown"} /></Table.Td>
                    <Table.Td>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        <Button component="a" href={`/servers/${server.ID}/server_configuration`} size="xs" variant="light">Configure</Button>
                        <ActionForm action={`/servers/${server.ID}/delete`} fields={{}} confirmMessage="Delete this server?"><Button type="submit" size="xs" color="red" variant="subtle" leftSection={<IconTrash size={14} />}>Delete</Button></ActionForm>
                      </div>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Paper>
      <Modal opened={opened} onClose={close} title="Add Server" centered>
        <form method="post" action="/servers/new">
          <Stack>
            <TextInput label="Friendly Name" name="friendlyName" required />
            <TextInput label="Desired VPN IP" name="desiredIP" defaultValue={page.SuggestedIP} required />
            <Button type="submit">Save Server</Button>
          </Stack>
        </form>
      </Modal>
    </Container>
  );
}

export function SettingsPageView({ page }) {
  const groups = useMemo(() => (page.Data?.Items || []).reduce((accumulator, item) => {
    const group = item.Group || "General";
    accumulator[group] = accumulator[group] || [];
    accumulator[group].push(item);
    return accumulator;
  }, {}), [page.Data]);
  const copyValue = async (value) => {
    try {
      await navigator.clipboard.writeText(value || "");
    } catch {
      window.alert("Clipboard access denied.");
    }
  };
  return (
    <Container fluid>
      <PageHeader title="Settings" description="Edit runtime settings without repeating the form markup across templates." actions={page.Data?.Saved ? <Badge color="teal">Saved</Badge> : null} />
      <form method="post" action="/settings">
        <Stack gap="lg">
          {Object.entries(groups).map(([group, items]) => (
            <Paper key={group} radius="xl" p="lg" className="soft-panel">
              <Stack gap="md">
                <div><Title order={4}>{group}</Title></div>
                {items.map((item) => (
                  <Paper key={item.Key} radius="lg" p="md" className="shell-panel">
                    <Stack gap="xs">
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "start", flexWrap: "wrap" }}>
                        <div><Text fw={600}>{item.Label}</Text>{item.Help ? <Text size="sm" c="dimmed">{item.Help}</Text> : null}</div>
                        {item.ReadOnly ? <Button type="button" variant="light" color="gray" onClick={() => void copyValue(item.Value)}>Copy</Button> : null}
                      </div>
                      {item.Key === "dns.dnssec_public_key_json" ? (item.ReadOnly ? <Textarea name={item.Key} value={item.Value} readOnly minRows={8} autosize /> : <Textarea name={item.Key} defaultValue={item.Value} minRows={8} autosize />) : (item.ReadOnly ? <TextInput name={item.Key} value={item.Value} readOnly /> : <TextInput name={item.Key} defaultValue={item.Value} />)}
                      <Text size="xs" c="dimmed">Key: <Code className="code-chip">{item.Key}</Code></Text>
                    </Stack>
                  </Paper>
                ))}
              </Stack>
            </Paper>
          ))}
          <div style={{ display: "flex", justifyContent: "end" }}><Button type="submit">Save Settings</Button></div>
        </Stack>
      </form>
    </Container>
  );
}

