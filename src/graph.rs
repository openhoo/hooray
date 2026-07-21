use std::collections::{BTreeMap, BTreeSet, VecDeque};

use thiserror::Error;

use crate::model::{
    ComponentId, DependencyEdge, DependencyKind, DependencyPath, DependencyPaths, Inventory,
};

#[derive(Debug, Clone)]
pub struct DependencyGraph {
    nodes: BTreeSet<ComponentId>,
    outgoing: BTreeMap<ComponentId, BTreeSet<ComponentId>>,
    incoming: BTreeMap<ComponentId, BTreeSet<ComponentId>>,
    connected_roots: BTreeSet<ComponentId>,
    depth_from_root: BTreeMap<ComponentId, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GraphError {
    #[error("dependency references unknown component {0}")]
    UnknownComponent(ComponentId),
    #[error("component {0} depends on itself")]
    SelfDependency(ComponentId),
    #[error("dependency cycle detected: {0:?}")]
    Cycle(Vec<ComponentId>),
    #[error("path limit must be greater than zero")]
    ZeroPathLimit,
}

struct PathCollection<'a> {
    target: &'a ComponentId,
    max_depth: usize,
    max_paths: usize,
    paths: Vec<DependencyPath>,
    truncated: bool,
}

impl DependencyGraph {
    pub fn from_inventory(inventory: &Inventory) -> Result<Self, GraphError> {
        Self::new(
            inventory.components.keys().cloned(),
            &inventory.dependencies,
        )
    }

    pub fn new(
        nodes: impl IntoIterator<Item = ComponentId>,
        edges: &BTreeSet<DependencyEdge>,
    ) -> Result<Self, GraphError> {
        let nodes: BTreeSet<_> = nodes.into_iter().collect();
        let mut outgoing: BTreeMap<_, BTreeSet<_>> = nodes
            .iter()
            .cloned()
            .map(|node| (node, BTreeSet::new()))
            .collect();
        let mut incoming = outgoing.clone();
        for edge in edges {
            if !nodes.contains(&edge.from) {
                return Err(GraphError::UnknownComponent(edge.from.clone()));
            }
            if !nodes.contains(&edge.to) {
                return Err(GraphError::UnknownComponent(edge.to.clone()));
            }
            if edge.from == edge.to {
                return Err(GraphError::SelfDependency(edge.from.clone()));
            }
            outgoing
                .get_mut(&edge.from)
                .unwrap()
                .insert(edge.to.clone());
            incoming
                .get_mut(&edge.to)
                .unwrap()
                .insert(edge.from.clone());
        }
        let connected_roots: BTreeSet<_> = nodes
            .iter()
            .filter(|node| incoming[*node].is_empty())
            .filter(|node| !outgoing[*node].is_empty() || nodes.len() == 1)
            .cloned()
            .collect();
        let depth_from_root = shortest_depths(&connected_roots, &outgoing);
        let graph = Self {
            nodes,
            outgoing,
            incoming,
            connected_roots,
            depth_from_root,
        };
        if let Some(cycle) = graph.find_cycle() {
            return Err(GraphError::Cycle(cycle));
        }
        Ok(graph)
    }

    pub fn roots(&self) -> BTreeSet<ComponentId> {
        self.nodes
            .iter()
            .filter(|node| self.incoming[*node].is_empty())
            .cloned()
            .collect()
    }

    fn connected_roots(&self) -> &BTreeSet<ComponentId> {
        &self.connected_roots
    }
    pub fn classify(&self, component: &ComponentId) -> Result<DependencyKind, GraphError> {
        self.require_node(component)?;
        match self.depth_from_root.get(component) {
            Some(1) => Ok(DependencyKind::Direct),
            Some(depth) if *depth > 1 => Ok(DependencyKind::Transitive),
            _ => Ok(DependencyKind::Disconnected),
        }
    }

    pub fn shortest_path(
        &self,
        target: &ComponentId,
    ) -> Result<Option<DependencyPath>, GraphError> {
        self.require_node(target)?;
        let roots = self.connected_roots();
        let mut queue: VecDeque<ComponentId> = roots.iter().cloned().collect();
        let mut parent: BTreeMap<ComponentId, Option<ComponentId>> =
            roots.iter().cloned().map(|root| (root, None)).collect();
        while let Some(node) = queue.pop_front() {
            if &node == target {
                let mut components = Vec::new();
                let mut current = Some(node);
                while let Some(component) = current {
                    current = parent[&component].clone();
                    components.push(component);
                }
                components.reverse();
                return Ok(Some(DependencyPath { components }));
            }
            for next in &self.outgoing[&node] {
                if parent.contains_key(next) {
                    continue;
                }
                parent.insert(next.clone(), Some(node.clone()));
                queue.push_back(next.clone());
            }
        }
        Ok(None)
    }

    pub fn all_paths(
        &self,
        target: &ComponentId,
        max_depth: usize,
        max_paths: usize,
    ) -> Result<DependencyPaths, GraphError> {
        self.require_node(target)?;
        if max_paths == 0 {
            return Err(GraphError::ZeroPathLimit);
        }
        let mut collection = PathCollection {
            target,
            max_depth,
            max_paths,
            paths: Vec::new(),
            truncated: false,
        };
        let mut roots = self.connected_roots().iter().cloned();
        while let Some(root) = roots.next() {
            if !self.can_reach(&root, target) {
                continue;
            }
            let mut current = vec![root];
            if self.collect_paths(&mut collection, &mut current) {
                break;
            }
            if collection.paths.len() == max_paths {
                collection.truncated = roots.any(|remaining| self.can_reach(&remaining, target));
                break;
            }
        }
        collection.paths.sort();
        Ok(DependencyPaths {
            paths: collection.paths,
            truncated: collection.truncated,
        })
    }

    fn collect_paths(
        &self,
        collection: &mut PathCollection<'_>,
        current: &mut Vec<ComponentId>,
    ) -> bool {
        let node = current.last().unwrap();
        if node == collection.target {
            if collection.paths.len() < collection.max_paths {
                collection.paths.push(DependencyPath {
                    components: current.clone(),
                });
            }
            return collection.truncated && collection.paths.len() == collection.max_paths;
        }
        if current.len() > collection.max_depth {
            if self.can_reach(node, collection.target) {
                collection.truncated = true;
            }
            return collection.truncated && collection.paths.len() == collection.max_paths;
        }
        let mut outgoing = self.outgoing[node].iter();
        while let Some(next) = outgoing.next() {
            current.push(next.clone());
            let stop = self.collect_paths(collection, current);
            current.pop();
            if stop {
                return true;
            }
            if collection.paths.len() == collection.max_paths {
                if outgoing.any(|remaining| self.can_reach(remaining, collection.target)) {
                    collection.truncated = true;
                    return true;
                }
                return false;
            }
        }
        false
    }

    fn can_reach(&self, start: &ComponentId, target: &ComponentId) -> bool {
        let mut pending = vec![start.clone()];
        let mut seen = BTreeSet::new();
        while let Some(node) = pending.pop() {
            if !seen.insert(node.clone()) {
                continue;
            }
            if &node == target {
                return true;
            }
            pending.extend(self.outgoing[&node].iter().rev().cloned());
        }
        false
    }

    fn require_node(&self, component: &ComponentId) -> Result<(), GraphError> {
        if self.nodes.contains(component) {
            Ok(())
        } else {
            Err(GraphError::UnknownComponent(component.clone()))
        }
    }

    fn find_cycle(&self) -> Option<Vec<ComponentId>> {
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut path = Vec::new();

        for start in &self.nodes {
            if visited.contains(start) {
                continue;
            }
            let mut pending = vec![(start.clone(), false)];
            while let Some((node, exiting)) = pending.pop() {
                if exiting {
                    path.pop();
                    visiting.remove(&node);
                    visited.insert(node);
                    continue;
                }
                if visited.contains(&node) {
                    continue;
                }
                if visiting.contains(&node) {
                    let cycle_start = path.iter().position(|item| item == &node).unwrap();
                    let mut cycle = path[cycle_start..].to_vec();
                    cycle.push(node);
                    return Some(cycle);
                }

                visiting.insert(node.clone());
                path.push(node.clone());
                pending.push((node.clone(), true));
                pending.extend(
                    self.outgoing[&node]
                        .iter()
                        .rev()
                        .cloned()
                        .map(|next| (next, false)),
                );
            }
        }
        None
    }
}

fn shortest_depths(
    roots: &BTreeSet<ComponentId>,
    outgoing: &BTreeMap<ComponentId, BTreeSet<ComponentId>>,
) -> BTreeMap<ComponentId, usize> {
    let mut depths: BTreeMap<ComponentId, usize> =
        roots.iter().cloned().map(|root| (root, 0)).collect();
    let mut queue: VecDeque<ComponentId> = roots.iter().cloned().collect();
    while let Some(node) = queue.pop_front() {
        let depth = depths[&node];
        for next in &outgoing[&node] {
            if depths.contains_key(next) {
                continue;
            }
            depths.insert(next.clone(), depth + 1);
            queue.push_back(next.clone());
        }
    }
    depths
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::model::{ComponentId, DependencyEdge, DependencyKind, Scope};

    use super::{DependencyGraph, GraphError};

    fn id(value: &str) -> ComponentId {
        ComponentId::new(value).unwrap()
    }
    fn edge(from: &str, to: &str) -> DependencyEdge {
        DependencyEdge {
            from: id(from),
            to: id(to),
            scope: Scope::Runtime,
            optional: false,
        }
    }
    fn graph(nodes: &[&str], edges: &[DependencyEdge]) -> Result<DependencyGraph, GraphError> {
        DependencyGraph::new(
            nodes.iter().map(|value| id(value)),
            &edges.iter().cloned().collect(),
        )
    }

    #[test]
    fn rejects_unknown_self_and_cyclic_dependencies_deterministically() {
        assert_eq!(
            graph(&["a"], &[edge("a", "missing")]).unwrap_err(),
            GraphError::UnknownComponent(id("missing"))
        );
        assert_eq!(
            graph(&["a"], &[edge("a", "a")]).unwrap_err(),
            GraphError::SelfDependency(id("a"))
        );
        assert_eq!(
            graph(
                &["a", "b", "c"],
                &[edge("a", "b"), edge("b", "c"), edge("c", "a")]
            )
            .unwrap_err(),
            GraphError::Cycle(vec![id("a"), id("b"), id("c"), id("a")])
        );
    }

    #[test]
    fn roots_are_not_dependencies_and_children_are_classified_by_depth() {
        let graph = graph(&["a", "b", "c", "d"], &[edge("a", "b"), edge("b", "d")]).unwrap();
        assert_eq!(graph.roots(), BTreeSet::from([id("a"), id("c")]));
        assert_eq!(
            graph.classify(&id("a")).unwrap(),
            DependencyKind::Disconnected
        );
        assert_eq!(graph.classify(&id("b")).unwrap(), DependencyKind::Direct);
        assert_eq!(
            graph.classify(&id("d")).unwrap(),
            DependencyKind::Transitive
        );
        assert_eq!(
            graph.classify(&id("c")).unwrap(),
            DependencyKind::Disconnected
        );
    }

    #[test]
    fn shortest_path_uses_length_then_lexical_order_across_roots() {
        let graph = graph(
            &["a", "b", "c", "d", "z"],
            &[
                edge("a", "c"),
                edge("c", "d"),
                edge("b", "d"),
                edge("z", "d"),
            ],
        )
        .unwrap();
        assert_eq!(
            graph.shortest_path(&id("d")).unwrap().unwrap().components,
            vec![id("b"), id("d")]
        );
    }

    #[test]
    fn all_paths_are_ordered_and_report_count_truncation() {
        let graph = graph(
            &["a", "b", "c", "d", "e"],
            &[
                edge("a", "c"),
                edge("a", "d"),
                edge("b", "d"),
                edge("c", "e"),
                edge("d", "e"),
            ],
        )
        .unwrap();
        let result = graph.all_paths(&id("e"), 3, 2).unwrap();
        assert_eq!(
            result
                .paths
                .iter()
                .map(|path| path.components.clone())
                .collect::<Vec<_>>(),
            vec![
                vec![id("a"), id("c"), id("e")],
                vec![id("a"), id("d"), id("e")],
            ]
        );
        assert!(result.truncated);
    }

    #[test]
    fn depth_bound_is_inclusive_and_reports_omitted_paths() {
        let graph = graph(&["a", "b", "c"], &[edge("a", "b"), edge("b", "c")]).unwrap();
        let shallow = graph.all_paths(&id("c"), 1, 10).unwrap();
        assert!(shallow.paths.is_empty());
        assert!(shallow.truncated);
        let exact = graph.all_paths(&id("c"), 2, 10).unwrap();
        assert_eq!(exact.paths[0].edge_count(), 2);
        assert!(!exact.truncated);
    }

    #[test]
    fn zero_path_limit_is_explicitly_rejected() {
        let graph = graph(&["a"], &[]).unwrap();
        assert_eq!(
            graph.all_paths(&id("a"), 0, 0).unwrap_err(),
            GraphError::ZeroPathLimit
        );
    }
    #[test]
    fn layered_dag_limits_shortest_and_all_path_work() {
        const LAYERS: usize = 24;
        let root = id("root");
        let target = id("target");
        let layers: Vec<[ComponentId; 2]> = (0..LAYERS)
            .map(|index| {
                [
                    id(&format!("layer-{index:02}-a")),
                    id(&format!("layer-{index:02}-b")),
                ]
            })
            .collect();
        let mut nodes = BTreeSet::from([root.clone(), target.clone()]);
        nodes.extend(layers.iter().flatten().cloned());
        let mut edges = BTreeSet::new();
        for first in &layers[0] {
            edges.insert(DependencyEdge {
                from: root.clone(),
                to: first.clone(),
                scope: Scope::Runtime,
                optional: false,
            });
        }
        for adjacent in layers.windows(2) {
            for from in &adjacent[0] {
                for to in &adjacent[1] {
                    edges.insert(DependencyEdge {
                        from: from.clone(),
                        to: to.clone(),
                        scope: Scope::Runtime,
                        optional: false,
                    });
                }
            }
        }
        for last in &layers[LAYERS - 1] {
            edges.insert(DependencyEdge {
                from: last.clone(),
                to: target.clone(),
                scope: Scope::Runtime,
                optional: false,
            });
        }
        let graph = DependencyGraph::new(nodes, &edges).unwrap();

        let mut expected = vec![root];
        expected.extend(layers.iter().map(|layer| layer[0].clone()));
        expected.push(target.clone());
        assert_eq!(
            graph.shortest_path(&target).unwrap().unwrap().components,
            expected
        );

        let paths = graph.all_paths(&target, LAYERS + 1, 2).unwrap();
        assert_eq!(paths.paths.len(), 2);
        assert!(paths.truncated);
    }

    #[test]
    fn long_acyclic_chain_uses_iterative_cycle_detection() {
        const NODE_COUNT: usize = 20_000;
        let nodes: Vec<_> = (0..NODE_COUNT)
            .map(|index| id(&format!("node-{index:05}")))
            .collect();
        let edges = nodes
            .windows(2)
            .map(|pair| DependencyEdge {
                from: pair[0].clone(),
                to: pair[1].clone(),
                scope: Scope::Runtime,
                optional: false,
            })
            .collect();

        let graph = DependencyGraph::new(nodes.clone(), &edges).unwrap();
        let path = graph.shortest_path(nodes.last().unwrap()).unwrap().unwrap();
        assert_eq!(path.components.len(), NODE_COUNT);
        assert_eq!(path.components.first(), nodes.first());
        assert_eq!(path.components.last(), nodes.last());
    }
}
